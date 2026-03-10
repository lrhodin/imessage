package connector

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ogMetaRegex matches <meta property="og:..." content="..."> in either attribute order,
// supporting both single and double quoted attribute values.
var ogMetaRegex = regexp.MustCompile(
	`(?i)<meta\s+[^>]*(?:property|name)=["']og:([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*/?>` +
		`|` +
		`(?i)<meta\s+[^>]*content=["']([^"']*)["'][^>]*(?:property|name)=["']og:([^"']+)["'][^>]*/?>`,
)

// fetchURLPreview builds a BeeperLinkPreview by fetching the target URL's Open Graph
// metadata. It tries the homeserver's /preview_url first, then falls back to fetching
// the HTML and parsing og: meta tags directly. If an og:image is found, it is downloaded
// and uploaded via the provided intent. The roomID is required so that UploadMedia
// encrypts the image in E2EE rooms (matching mautrix-whatsapp behavior).
func fetchURLPreview(ctx context.Context, bridge *bridgev2.Bridge, intent bridgev2.MatrixAPI, roomID id.RoomID, targetURL string) *event.BeeperLinkPreview {
	log := zerolog.Ctx(ctx)

	fetchURL := normalizeURL(targetURL)

	preview := &event.BeeperLinkPreview{
		MatchedURL: targetURL,
		LinkPreview: event.LinkPreview{
			CanonicalURL: fetchURL,
			Title:        targetURL,
		},
	}

	// Try homeserver preview first
	if mc, ok := bridge.Matrix.(bridgev2.MatrixConnectorWithURLPreviews); ok {
		lp, err := mc.GetURLPreview(ctx, fetchURL)
		if err != nil {
			log.Debug().Err(err).Str("url", fetchURL).Msg("Homeserver URL preview failed, falling back to og: scraping")
		}
		if err == nil && lp != nil {
			preview.LinkPreview = *lp
			if preview.CanonicalURL == "" {
				preview.CanonicalURL = targetURL
			}
			if preview.Title == "" {
				preview.Title = targetURL
			}
			// If homeserver already returned an image, we're done
			if preview.ImageURL != "" {
				return preview
			}
		}
	}

	// Fetch the page ourselves and parse og: metadata
	ogData := fetchOGMetadata(ctx, fetchURL)
	if ogData["title"] != "" && preview.Title == targetURL {
		preview.Title = ogData["title"]
	}
	if ogData["description"] != "" && preview.Description == "" {
		preview.Description = ogData["description"]
	}

	// Download and upload og:image
	imageURL := ogData["image"]
	if imageURL == "" {
		imageURL = ogData["image:secure_url"]
	}
	if imageURL != "" && intent != nil {
		// Resolve relative URLs against the normalized (https://) URL
		if !strings.HasPrefix(imageURL, "http") {
			if base, err := url.Parse(fetchURL); err == nil {
				if ref, err := url.Parse(imageURL); err == nil {
					imageURL = base.ResolveReference(ref).String()
				}
			}
		}
		data, mime, err := downloadURL(ctx, imageURL)
		if err == nil && len(data) > 0 {
			mxcURL, encFile, err := intent.UploadMedia(ctx, roomID, data, "preview", mime)
			if err == nil {
				if encFile != nil {
					preview.ImageEncryption = encFile
					preview.ImageURL = encFile.URL
				} else {
					preview.ImageURL = mxcURL
				}
				preview.ImageType = mime
				preview.ImageSize = event.IntOrString(len(data))
				log.Debug().Str("og_image", imageURL).Msg("Uploaded URL preview image")
			} else {
				log.Debug().Err(err).Msg("Failed to upload URL preview image")
			}
		} else if err != nil {
			log.Debug().Err(err).Str("og_image", imageURL).Msg("Failed to download URL preview image")
		}
	}

	return preview
}

// userAgents lists User-Agent strings to try when fetching og: metadata.
// Some sites (e.g. x.com) only serve og: tags to known crawlers, while
// others (e.g. Reddit) block bot UAs. We try a browser UA first (works
// for most sites), then fall back to a bot UA for JS-heavy SPAs.
var userAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
}

// fetchOGMetadata fetches a URL and extracts Open Graph meta tags from the HTML.
// It tries multiple User-Agent strings to handle sites that only serve og: tags
// to recognized crawlers.
func fetchOGMetadata(ctx context.Context, targetURL string) map[string]string {
	log := zerolog.Ctx(ctx)

	for _, ua := range userAgents {
		result := fetchOGMetadataWithUA(ctx, targetURL, ua)
		if result["image"] != "" || result["title"] != "" {
			return result
		}
		log.Debug().Str("ua", ua).Str("url", targetURL).Msg("No og: metadata found with this UA, trying next")
	}

	return make(map[string]string)
}

// fetchOGMetadataWithUA fetches a URL with a specific User-Agent and extracts og: tags.
func fetchOGMetadataWithUA(ctx context.Context, targetURL string, ua string) map[string]string {
	result := make(map[string]string)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return result
	}

	// Read first 512KB — og: meta tags should be in <head> but some sites
	// (e.g. CNN) inline hundreds of KB of CSS/JS before their meta tags.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if len(data) == 0 {
		return result
	}
	htmlStr := string(data)

	for _, match := range ogMetaRegex.FindAllStringSubmatch(htmlStr, -1) {
		var prop, content string
		if match[1] != "" {
			prop, content = match[1], match[2]
		} else {
			prop, content = match[4], match[3]
		}
		prop = strings.ToLower(prop)
		if _, exists := result[prop]; !exists {
			result[prop] = html.UnescapeString(content)
		}
	}

	return result
}

// downloadURL fetches a URL and returns the body bytes and content type.
func downloadURL(ctx context.Context, targetURL string) ([]byte, string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, targetURL)
	}

	// Limit to 5MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, "", err
	}

	mime := resp.Header.Get("Content-Type")
	if i := strings.Index(mime, ";"); i >= 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	if mime == "" {
		mime = "image/jpeg"
	}

	return data, mime, nil
}
