// extract-key: Reads hardware identifiers from this Mac and outputs
// a base64-encoded JSON hardware key for the iMessage bridge.
//
// Usage:
//
//	cd tools/extract-key && go run main.go
//	# or
//	go run tools/extract-key/main.go
//
// This only READS data from IOKit — nothing is modified on the Mac.
// The Mac can continue to be used normally, including for iMessage.
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework IOKit -framework DiskArbitration

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <DiskArbitration/DiskArbitration.h>

// Both kIOMainPortDefault (macOS 12+) and kIOMasterPortDefault (deprecated in 12)
// are MACH_PORT_NULL. Use 0 directly for compatibility back to 10.13 High Sierra.
#define IO_PORT_DEFAULT MACH_PORT_NULL
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>

// Read a string property from an IOKit registry entry
static char* io_string(io_service_t svc, CFStringRef key) {
    CFTypeRef ref = IORegistryEntryCreateCFProperty(svc, key, kCFAllocatorDefault, 0);
    if (!ref) return NULL;
    if (CFGetTypeID(ref) == CFStringGetTypeID()) {
        char buf[256];
        if (CFStringGetCString((CFStringRef)ref, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            CFRelease(ref);
            return strdup(buf);
        }
    }
    CFRelease(ref);
    return NULL;
}

// Read a data property from an IOKit registry entry, return as bytes
static void io_data(io_service_t svc, CFStringRef key, unsigned char **out, int *out_len) {
    *out = NULL;
    *out_len = 0;
    CFTypeRef ref = IORegistryEntryCreateCFProperty(svc, key, kCFAllocatorDefault, 0);
    if (!ref) return;
    if (CFGetTypeID(ref) == CFDataGetTypeID()) {
        CFDataRef data = (CFDataRef)ref;
        int len = (int)CFDataGetLength(data);
        *out = (unsigned char*)malloc(len);
        memcpy(*out, CFDataGetBytePtr(data), len);
        *out_len = len;
    }
    CFRelease(ref);
}

// Get the en0 MAC address
static void get_mac_address(unsigned char **out, int *out_len) {
    *out = NULL;
    *out_len = 0;
    struct ifaddrs *ifas;
    if (getifaddrs(&ifas) != 0) return;
    for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK && strcmp(ifa->ifa_name, "en0") == 0) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_alen == 6) {
                *out = (unsigned char*)malloc(6);
                memcpy(*out, LLADDR(sdl), 6);
                *out_len = 6;
                break;
            }
        }
    }
    freeifaddrs(ifas);
}

// Get root disk UUID
static char* get_root_disk_uuid() {
    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    if (!session) return strdup("unknown");

    struct statfs sfs;
    if (statfs("/", &sfs) != 0) {
        CFRelease(session);
        return strdup("unknown");
    }

    DADiskRef disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, sfs.f_mntfromname);
    if (!disk) {
        CFRelease(session);
        return strdup("unknown");
    }

    CFDictionaryRef desc = DADiskCopyDescription(disk);
    char *result = strdup("unknown");
    if (desc) {
        CFUUIDRef uuid = CFDictionaryGetValue(desc, kDADiskDescriptionVolumeUUIDKey);
        if (uuid) {
            CFStringRef str = CFUUIDCreateString(kCFAllocatorDefault, uuid);
            if (str) {
                char buf[128];
                if (CFStringGetCString(str, buf, sizeof(buf), kCFStringEncodingUTF8)) {
                    free(result);
                    result = strdup(buf);
                }
                CFRelease(str);
            }
        }
        CFRelease(desc);
    }
    CFRelease(disk);
    CFRelease(session);
    return result;
}

struct hw_result {
    // Plain-text identifiers
    char *serial_number;
    char *platform_uuid;
    char *board_id;
    char *product_name;
    char *os_build_num;
    char *root_disk_uuid;
    char *mlb;
    unsigned char *rom;
    int rom_len;
    unsigned char *mac_address;
    int mac_address_len;

    // Encrypted/obfuscated IOKit properties (already stored by macOS)
    unsigned char *serial_enc;      // Gq3489ugfi
    int serial_enc_len;
    unsigned char *uuid_enc;        // Fyp98tpgj
    int uuid_enc_len;
    unsigned char *disk_uuid_enc;   // kbjfrfpoJU
    int disk_uuid_enc_len;
    unsigned char *rom_enc;         // oycqAZloTNDm
    int rom_enc_len;
    unsigned char *mlb_enc;         // abKPld1EcMni
    int mlb_enc_len;

    char *error;
};

static struct hw_result read_hardware() {
    struct hw_result r;
    memset(&r, 0, sizeof(r));

    io_service_t platform = IOServiceGetMatchingService(IO_PORT_DEFAULT,
        IOServiceMatching("IOPlatformExpertDevice"));
    if (!platform) {
        r.error = strdup("failed to find IOPlatformExpertDevice");
        return r;
    }

    // Plain-text identifiers
    r.serial_number = io_string(platform, CFSTR("IOPlatformSerialNumber"));
    r.platform_uuid = io_string(platform, CFSTR("IOPlatformUUID"));

    // board-id: try string first, then data (null-terminated)
    r.board_id = io_string(platform, CFSTR("board-id"));
    if (!r.board_id) {
        unsigned char *bdata; int blen;
        io_data(platform, CFSTR("board-id"), &bdata, &blen);
        if (bdata && blen > 0) {
            r.board_id = strndup((char*)bdata, blen);
            free(bdata);
        }
    }
    // Same for product-name
    r.product_name = io_string(platform, CFSTR("product-name"));
    if (!r.product_name) {
        unsigned char *pdata; int plen;
        io_data(platform, CFSTR("product-name"), &pdata, &plen);
        if (pdata && plen > 0) {
            r.product_name = strndup((char*)pdata, plen);
            free(pdata);
        }
    }
    // Fallback to hw.model for product_name
    if (!r.product_name) {
        char buf[64];
        size_t len = sizeof(buf);
        if (sysctlbyname("hw.model", buf, &len, NULL, 0) == 0) {
            r.product_name = strdup(buf);
        }
    }

    // ROM and MLB (EFI NVRAM)
    io_data(platform, CFSTR("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM"), &r.rom, &r.rom_len);
    r.mlb = io_string(platform, CFSTR("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"));
    if (!r.mlb) {
        // Try as data
        unsigned char *mdata; int mlen;
        io_data(platform, CFSTR("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"), &mdata, &mlen);
        if (mdata && mlen > 0) {
            r.mlb = strndup((char*)mdata, mlen);
            free(mdata);
        }
    }

    // Encrypted/obfuscated properties — present on Intel Macs in IOKit.
    // On Apple Silicon these don't exist in the registry.
    io_data(platform, CFSTR("Gq3489ugfi"),   &r.serial_enc,    &r.serial_enc_len);
    io_data(platform, CFSTR("Fyp98tpgj"),    &r.uuid_enc,      &r.uuid_enc_len);
    io_data(platform, CFSTR("kbjfrfpoJU"),   &r.disk_uuid_enc, &r.disk_uuid_enc_len);
    io_data(platform, CFSTR("oycqAZloTNDm"), &r.rom_enc,       &r.rom_enc_len);
    io_data(platform, CFSTR("abKPld1EcMni"), &r.mlb_enc,       &r.mlb_enc_len);

    // On Apple Silicon, ROM is not in NVRAM — derive from en0 MAC address.
    // Only do this on ARM; on Intel we fall through to nvram CLI below.
#if defined(__arm64__)
    if (r.rom == NULL || r.rom_len == 0) {
        get_mac_address(&r.rom, &r.rom_len);
    }
#endif

    // On Apple Silicon, MLB is under "mlb-serial-number" as padded data
    if (!r.mlb) {
        unsigned char *mdata; int mlen;
        io_data(platform, CFSTR("mlb-serial-number"), &mdata, &mlen);
        if (mdata && mlen > 0) {
            // Strip trailing null padding
            while (mlen > 0 && mdata[mlen-1] == 0) mlen--;
            if (mlen > 0) {
                r.mlb = strndup((char*)mdata, mlen);
            }
            free(mdata);
        }
    }

    IOObjectRelease(platform);

    // Fallback: read ROM and MLB from IODeviceTree:/options (NVRAM node).
    // On macOS 10.13 High Sierra, the NVRAM GUID-prefixed properties may not
    // be exposed on IOPlatformExpertDevice but are available on the options node.
    if (!r.mlb || (r.rom == NULL || r.rom_len == 0)) {
        io_registry_entry_t options = IORegistryEntryFromPath(IO_PORT_DEFAULT, "IODeviceTree:/options");
        if (options) {
            if (!r.mlb) {
                r.mlb = io_string(options, CFSTR("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"));
                if (!r.mlb) {
                    unsigned char *mdata; int mlen;
                    io_data(options, CFSTR("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"), &mdata, &mlen);
                    if (mdata && mlen > 0) {
                        // Strip trailing null padding
                        while (mlen > 0 && mdata[mlen-1] == 0) mlen--;
                        if (mlen > 0) r.mlb = strndup((char*)mdata, mlen);
                        free(mdata);
                    }
                }
            }
            if (r.rom == NULL || r.rom_len == 0) {
                io_data(options, CFSTR("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM"), &r.rom, &r.rom_len);
            }
            IOObjectRelease(options);
        }
    }

    // Fallback: shell out to `nvram` CLI which uses a different code path
    // and works on Macs where the IODeviceTree properties above aren't found
    // (e.g. MacBookAir7,2).
    if (r.rom == NULL || r.rom_len == 0) {
        FILE *fp = popen("nvram '4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM' 2>/dev/null", "r");
        if (fp) {
            char buf[512];
            if (fgets(buf, sizeof(buf), fp)) {
                // nvram output: "4D1EDE05-...:ROM\t<value>"
                // Value is percent-encoded binary: $%1e%eb%08n%ae
                char *tab = strchr(buf, '\t');
                if (tab) {
                    tab++; // skip tab
                    char *nl = strchr(tab, '\n');
                    if (nl) *nl = '\0';
                    // Decode percent-encoded binary
                    int alloc = (int)strlen(tab);
                    unsigned char *decoded = (unsigned char*)malloc(alloc);
                    int dlen = 0;
                    for (int i = 0; tab[i]; i++) {
                        if (tab[i] == '%' && tab[i+1] && tab[i+2]) {
                            char hex[3] = {tab[i+1], tab[i+2], 0};
                            decoded[dlen++] = (unsigned char)strtol(hex, NULL, 16);
                            i += 2;
                        } else {
                            decoded[dlen++] = (unsigned char)tab[i];
                        }
                    }
                    if (dlen > 0) {
                        r.rom = decoded;
                        r.rom_len = dlen;
                    } else {
                        free(decoded);
                    }
                }
            }
            pclose(fp);
        }
    }
    if (!r.mlb) {
        FILE *fp = popen("nvram '4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB' 2>/dev/null", "r");
        if (fp) {
            char buf[512];
            if (fgets(buf, sizeof(buf), fp)) {
                char *tab = strchr(buf, '\t');
                if (tab) {
                    tab++;
                    char *nl = strchr(tab, '\n');
                    if (nl) *nl = '\0';
                    if (strlen(tab) > 0) {
                        r.mlb = strdup(tab);
                    }
                }
            }
            pclose(fp);
        }
    }

    // OS build number
    {
        char buf[64];
        size_t len = sizeof(buf);
        if (sysctlbyname("kern.osversion", buf, &len, NULL, 0) == 0)
            r.os_build_num = strdup(buf);
        else
            r.os_build_num = strdup("unknown");
    }

    // Root disk UUID
    r.root_disk_uuid = get_root_disk_uuid();

    // en0 MAC address
    get_mac_address(&r.mac_address, &r.mac_address_len);

    return r;
}
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

// Bytes is a []byte that marshals to a JSON array of ints (matching Rust's serde
// bin_serialize/bin_deserialize) instead of Go's default base64 string.
// Empty/nil serializes as [] instead of null.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return []byte("[]"), nil
	}
	arr := make([]int, len(b))
	for i, v := range b {
		arr[i] = int(v)
	}
	return json.Marshal(arr)
}

// HardwareConfig matches rustpush/open-absinthe/src/nac.rs HardwareConfig exactly
type HardwareConfig struct {
	ProductName             string `json:"product_name"`
	IOMacAddress            Bytes  `json:"io_mac_address"`
	PlatformSerialNumber    string `json:"platform_serial_number"`
	PlatformUUID            string `json:"platform_uuid"`
	RootDiskUUID            string `json:"root_disk_uuid"`
	BoardID                 string `json:"board_id"`
	OSBuildNum              string `json:"os_build_num"`
	PlatformSerialNumberEnc Bytes  `json:"platform_serial_number_enc"`
	PlatformUUIDEnc         Bytes  `json:"platform_uuid_enc"`
	RootDiskUUIDEnc         Bytes  `json:"root_disk_uuid_enc"`
	ROM                     Bytes  `json:"rom"`
	ROMEnc                  Bytes  `json:"rom_enc"`
	MLB                     string `json:"mlb"`
	MLBEnc                  Bytes  `json:"mlb_enc"`
}

// MacOSConfig matches rustpush/src/macos.rs MacOSConfig
type MacOSConfig struct {
	Inner           HardwareConfig `json:"inner"`
	Version         string         `json:"version"`
	ProtocolVersion uint32         `json:"protocol_version"`
	DeviceID        string         `json:"device_id"`
	ICloudUA        string         `json:"icloud_ua"`
	AOSKitVersion   string         `json:"aoskit_version"`
	NACRelayURL     string         `json:"nac_relay_url,omitempty"`
	RelayToken      string         `json:"relay_token,omitempty"`
	RelayCertFP     string         `json:"relay_cert_fp,omitempty"`
}

// relayInfo matches the relay-info.json written by nac-relay.
type relayInfo struct {
	Token           string `json:"token"`
	CertFingerprint string `json:"cert_fingerprint"`
}

// readRelayInfo reads ~/Library/Application Support/nac-relay/relay-info.json.
func readRelayInfo() (*relayInfo, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, "Library", "Application Support", "nac-relay", "relay-info.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info relayInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	if info.Token == "" || info.CertFingerprint == "" {
		return nil, fmt.Errorf("relay-info.json is incomplete (missing token or cert fingerprint)")
	}
	return &info, nil
}

func goBytes(p *C.uchar, n C.int) []byte {
	if p == nil || n <= 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p), n)
}

func goString(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

func getMacOSVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "14.0"
	}
	return strings.TrimSpace(string(out))
}

func getDarwinVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "22.5.0"
	}
	return strings.TrimSpace(string(out))
}

func main() {
	if runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "This tool must be run on macOS.")
		os.Exit(1)
	}

	relayURL := ""
	for i, arg := range os.Args[1:] {
		if arg == "-relay" && i+1 < len(os.Args)-1 {
			relayURL = os.Args[i+2]
		}
	}

	// If -relay is specified, read the auth credentials from relay-info.json.
	// The nac-relay must have been started at least once to generate these.
	var relayAuth *relayInfo
	if relayURL != "" {
		var err error
		relayAuth, err = readRelayInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "  ❌ Cannot read NAC relay credentials.\n")
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "  The NAC relay must be started before running extract-key so that\n")
			fmt.Fprintf(os.Stderr, "  TLS certificates and auth tokens are generated.\n")
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "  Start the relay first:\n")
			fmt.Fprintf(os.Stderr, "    go run tools/nac-relay/main.go\n")
			fmt.Fprintf(os.Stderr, "  Or install it as a service:\n")
			fmt.Fprintf(os.Stderr, "    go run tools/nac-relay/main.go --setup\n")
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "  Then re-run extract-key.\n")
			fmt.Fprintf(os.Stderr, "  (Error: %v)\n", err)
			fmt.Fprintf(os.Stderr, "\n")
			os.Exit(1)
		}
	}

	r := C.read_hardware()
	if r.error != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", C.GoString(r.error))
		C.free(unsafe.Pointer(r.error))
		os.Exit(1)
	}

	serial := goString(r.serial_number)
	platformUUID := goString(r.platform_uuid)
	rootDiskUUID := goString(r.root_disk_uuid)
	boardID := goString(r.board_id)
	osBuild := goString(r.os_build_num)
	productName := goString(r.product_name)

	// On Apple Silicon, board-id from IOKit may be empty.
	// Use the model identifier (e.g. "Mac14,14") as fallback.
	if boardID == "" && productName != "" {
		boardID = productName
	}
	mlb := goString(r.mlb)
	rom := goBytes(r.rom, C.int(r.rom_len))
	macAddr := goBytes(r.mac_address, C.int(r.mac_address_len))

	// Encrypted IOKit properties (read directly from the Mac's IOKit registry).
	// Present on Intel Macs; absent on Apple Silicon.
	serialEnc := Bytes(goBytes(r.serial_enc, C.int(r.serial_enc_len)))
	uuidEnc := Bytes(goBytes(r.uuid_enc, C.int(r.uuid_enc_len)))
	diskEnc := Bytes(goBytes(r.disk_uuid_enc, C.int(r.disk_uuid_enc_len)))
	romEnc := Bytes(goBytes(r.rom_enc, C.int(r.rom_enc_len)))
	mlbEnc := Bytes(goBytes(r.mlb_enc, C.int(r.mlb_enc_len)))

	version := getMacOSVersion()

	// Validate we got the critical fields
	missing := []string{}
	if serial == "" {
		missing = append(missing, "serial_number")
	}
	if platformUUID == "" {
		missing = append(missing, "platform_uuid")
	}
	if len(rom) == 0 {
		missing = append(missing, "ROM")
	}
	if mlb == "" {
		missing = append(missing, "MLB")
	}
	if len(macAddr) != 6 {
		missing = append(missing, "mac_address")
	}
	// Detect actual chip architecture (don't use _enc presence — High Sierra
	// Intel Macs also lack _enc fields).
	isAppleSilicon := runtime.GOARCH == "arm64"
	hasEncFields := len(serialEnc) > 0

	if isAppleSilicon && relayURL == "" {
		fmt.Fprintf(os.Stderr, "  ⚠️  Apple Silicon detected — encrypted IOKit properties are absent.\n")
		fmt.Fprintf(os.Stderr, "  The x86_64 NAC emulator on Linux will fail without them.\n")
		fmt.Fprintf(os.Stderr, "  You MUST run the NAC relay on this Mac and re-extract with:\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "    1. Start the relay:  go run tools/nac-relay/main.go\n")
		fmt.Fprintf(os.Stderr, "    2. Re-extract:       go run tools/extract-key/main.go -relay https://<this-ip>:5001/validation-data\n")
		fmt.Fprintf(os.Stderr, "\n")
	} else if isAppleSilicon && relayURL != "" {
		// Apple Silicon with relay — all good, suppress _enc warnings
	} else if !isAppleSilicon && !hasEncFields {
		// Intel Mac without _enc fields. This can happen on older macOS versions,
		// but seeing this on modern Intel builds is unusual and should be verified.
		fmt.Fprintf(os.Stderr, "  ⚠️  Encrypted IOKit properties not found on this Intel Mac.\n")
		fmt.Fprintf(os.Stderr, "  If registration fails (e.g. status 6004), capture native traffic on this Mac\n")
		fmt.Fprintf(os.Stderr, "  to confirm required fields/headers before relying on derived values.\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "  ⚠️  Could not read: %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(os.Stderr, "  The key may not work for iMessage registration.\n\n")
	}

	hw := HardwareConfig{
		ProductName:             productName,
		IOMacAddress:            Bytes(macAddr),
		PlatformSerialNumber:    serial,
		PlatformUUID:            platformUUID,
		RootDiskUUID:            rootDiskUUID,
		BoardID:                 boardID,
		OSBuildNum:              osBuild,
		PlatformSerialNumberEnc: serialEnc,
		PlatformUUIDEnc:         uuidEnc,
		RootDiskUUIDEnc:         diskEnc,
		ROM:                     Bytes(rom),
		ROMEnc:                  romEnc,
		MLB:                     mlb,
		MLBEnc:                  mlbEnc,
	}

	darwin := getDarwinVersion()
	icloudUA := fmt.Sprintf("com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/%s", darwin)

	config := MacOSConfig{
		Inner:           hw,
		Version:         version,
		ProtocolVersion: 1660,
		DeviceID:        strings.ToUpper(platformUUID),
		ICloudUA:        icloudUA,
		AOSKitVersion:   "com.apple.AOSKit/282 (com.apple.accountsd/113)",
		NACRelayURL:     relayURL,
	}
	if relayAuth != nil {
		config.RelayToken = relayAuth.Token
		config.RelayCertFP = relayAuth.CertFingerprint
	}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		os.Exit(1)
	}

	b64 := base64.StdEncoding.EncodeToString(jsonBytes)

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ✓ Hardware Key Extracted\n")
	fmt.Fprintf(os.Stderr, "  ───────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Model:   %s\n", productName)
	fmt.Fprintf(os.Stderr, "  Serial:  %s\n", serial)
	fmt.Fprintf(os.Stderr, "  Build:   %s (%s)\n", osBuild, version)
	fmt.Fprintf(os.Stderr, "  UUID:    %s\n", platformUUID)
	fmt.Fprintf(os.Stderr, "  MLB:     %s\n", mlb)
	fmt.Fprintf(os.Stderr, "  ROM:     %d bytes\n", len(rom))
	fmt.Fprintf(os.Stderr, "  MAC:     %02x:%02x:%02x:%02x:%02x:%02x\n",
		macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5])
	if isAppleSilicon {
		fmt.Fprintf(os.Stderr, "  Chip:    Apple Silicon\n")
	} else if hasEncFields {
		fmt.Fprintf(os.Stderr, "  Chip:    Intel (has _enc fields)\n")
	} else {
		fmt.Fprintf(os.Stderr, "  Chip:    Intel (no _enc fields — will be computed on Linux)\n")
	}
	if relayURL != "" {
		fmt.Fprintf(os.Stderr, "  Relay:   %s\n", relayURL)
	}
	if relayAuth != nil {
		fmt.Fprintf(os.Stderr, "  Auth:    token + TLS cert pinning\n")
		fmt.Fprintf(os.Stderr, "  CertFP:  %s...%s\n", relayAuth.CertFingerprint[:8], relayAuth.CertFingerprint[len(relayAuth.CertFingerprint)-8:])
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  This Mac can continue to be used normally.\n")
	fmt.Fprintf(os.Stderr, "  Paste the key below into the bridge login flow.\n")
	if relayURL != "" {
		fmt.Fprintf(os.Stderr, "  Keep the NAC relay running on this Mac.\n")
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Print base64 key to stdout (for easy copy/pipe)
	fmt.Println(b64)
}
