
// Implementing the SideStore Anisette v3 protocol

use std::{collections::HashMap, fs, io::Cursor, path::PathBuf};

use base64::engine::general_purpose;
use chrono::{DateTime, SubsecRound, Utc};
use clearadi::{AnisetteFlavor, ProvisionedMachine, ProvisioningSession};
use log::debug;
use plist::{Data, Dictionary};
use reqwest::{Certificate, Client, ClientBuilder, Proxy, RequestBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use rand::Rng;
use sha2::{Sha256, Digest};
use uuid::Uuid;
use std::fmt::Write;
use base64::Engine;
use async_trait::async_trait;

use crate::{AnisetteError, AnisetteProvider, LoginClientInfo};

const APPLE_ROOT: &[u8] = include_bytes!("../../icloud-auth/src/apple_root.der");

fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    Ok(s.try_into().unwrap())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(data.trim()).unwrap()
}


#[derive(Serialize, Deserialize, Clone)]
pub struct ProvisionedAnisette {
    client_secret: Data,
    mid: Data,
    metadata: Data,
    rinfo: String,
    #[serde(default)]
    flavor: ProvisionedFlavor,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub enum ProvisionedFlavor {
    #[default]
    Mac,
    IOS,
}

impl ProvisionedFlavor {
    fn anisette(&self) -> AnisetteFlavor {
        match self {
            Self::Mac => AnisetteFlavor::Mac,
            Self::IOS => AnisetteFlavor::IOS,
        }
    }
}

impl ProvisionedAnisette {
    fn new(machine: ProvisionedMachine, rinfo: &str, flavor: ProvisionedFlavor) -> ProvisionedAnisette {
        ProvisionedAnisette {
            client_secret: machine.client_secret.to_vec().into(),
            mid: machine.mid.to_vec().into(),
            metadata: machine.metadata.to_vec().into(),
            rinfo: rinfo.to_string(),
            flavor,
        }
    }

    fn machine(&self) -> ProvisionedMachine {
        ProvisionedMachine {
            client_secret: self.client_secret.as_ref().try_into().unwrap(),
            mid: self.mid.as_ref().try_into().unwrap(),
            metadata: self.metadata.as_ref().try_into().unwrap(),
            flavor: self.flavor.anisette(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_16")]
    keychain_identifier: [u8; 16],
    provisioned: Option<ProvisionedAnisette>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::thread_rng().gen::<[u8; 16]>(),
            provisioned: None
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn is_provisioned(&self) -> bool {
        self.provisioned.is_some()
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}
pub struct ClearADIClient {
    pub login_info: LoginClientInfo,
    pub configuration_path: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    local_user_id: String,
    device_unique_identifier: String
}

impl AnisetteData {
    pub fn get_headers(&self) -> HashMap<String, String> {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);
        
        HashMap::from_iter([
            ("X-Apple-I-Client-Time".to_string(), dt.format("%+").to_string().replace("+00:00", "Z")),
            ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
            ("X-Apple-Locale".to_string(), "en_US".to_string()),
            ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
            // ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
            ("X-Mme-Device-Id".to_string(), self.device_unique_identifier.clone()),
            ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
            ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
            ("X-Mme-Client-Info".to_string(), self.device_description.clone()),
        ].into_iter())
    }
}

fn make_reqwest() -> Result<Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        // .proxy(Proxy::https("https://192.168.99.87:8080").unwrap())
        // .danger_accept_invalid_certs(true)
        .build()?)
}

impl ClearADIClient {

    fn build_apple_request(&self, state: &AnisetteState, mut builder: RequestBuilder) -> RequestBuilder {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        // missing: Connection, Accept-Encdoing
        builder = builder.header("User-Agent", &self.login_info.akd_user_agent)
            .header("X-Apple-Baa-E", "-10000")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
            .header("X-Apple-Baa-Avail", "2")
            .header("X-Mme-Client-Info", &self.login_info.mme_client_info)
            .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("X-Apple-Client-App-Name", "akd")
            .header("Accept", "*/*")
            .header("Content-Type", "application/x-www-form-urlencoded") // not a bug, it's how you *think different*
            .header("X-Apple-Baa-UE", "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000")
            .header("X-Apple-Host-Baa-E", "-7066");

        for item in &self.login_info.hardware_headers {
            builder = builder.header(item.0, item.1);
        }

        builder
    }

    pub async fn get_headers(&self, state: &AnisetteState) -> Result<AnisetteData, AnisetteError> {
        let machine = state.provisioned.as_ref().ok_or(AnisetteError::AnisetteNotProvisioned)?;

        let otp = machine.machine().generate_otp();

        Ok(AnisetteData {
            machine_id: base64_encode(machine.mid.as_ref()),
            one_time_password: base64_encode(&otp),
            routing_info: machine.rinfo.clone(),
            device_description: self.login_info.mme_client_info.clone(),
            local_user_id: encode_hex(&state.md_lu()),
            device_unique_identifier: state.device_id()
        })
    }

    pub async fn provision(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        debug!("Provisioning Anisette");
        let http_client = make_reqwest()?;
        let resp = self.build_apple_request(&state, http_client.get("https://gsa.apple.com/grandslam/GsService2/lookup"))
            .send().await?;
        let text = resp.text().await?;

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let urls = protocol_val.as_dictionary().unwrap().get("urls").unwrap().as_dictionary().unwrap();

        let start_provisioning_url = urls.get("midStartProvisioning").unwrap().as_string().unwrap();
        let end_provisioning_url = urls.get("midFinishProvisioning").unwrap().as_string().unwrap();
        debug!("Got provisioning urls: {} and {}", start_provisioning_url, end_provisioning_url);

        let body_data = ProvisionBodyData { header: Dictionary::new(), request: Dictionary::new() };
        let resp = self.build_apple_request(state, http_client.post(start_provisioning_url))
            .body(plist_to_string(&body_data)?)
            .send().await?;
        let text = resp.text().await?;

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let spim = base64_decode(protocol_val.as_dictionary().unwrap().get("Response").unwrap().as_dictionary().unwrap()
        .get("spim").unwrap().as_string().unwrap());

        let flavor = if self.login_info.mme_client_info.contains("iPhone OS") {
            ProvisionedFlavor::IOS
        } else {
            ProvisionedFlavor::Mac
        };

        // TODO hostuuid
        let (session, cpim) = ProvisioningSession::new(&spim, &[], -2 /* GSA */, flavor.anisette())?;
        
        let body_data = ProvisionBodyData { header: Dictionary::new(), request: Dictionary::from_iter([("cpim", base64_encode(&cpim))].into_iter()) };
        let resp = self.build_apple_request(state, http_client.post(end_provisioning_url))
            .body(plist_to_string(&body_data)?)
            .send().await?;
        let text = resp.text().await?;

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let response = protocol_val.as_dictionary().unwrap().get("Response").unwrap().as_dictionary().unwrap();
        
        let ptm = response.get("ptm").unwrap().as_string().unwrap();
        let tk = response.get("tk").unwrap().as_string().unwrap();
        let rinfo = response.get("X-Apple-I-MD-RINFO").unwrap().as_string().unwrap();

        let machine = session.finish(&base64_decode(tk), &base64_decode(ptm))?;

        state.provisioned = Some(ProvisionedAnisette::new(machine, rinfo, flavor));

        Ok(())
    }
}

impl AnisetteProvider for ClearADIClient {
    async fn get_2fa_code(&mut self) -> Result<u32, AnisetteError> {
        fs::create_dir_all(&self.configuration_path)?;
        
        let config_path = self.configuration_path.join("state.plist");
        let mut state = if let Ok(text) = plist::from_file(&config_path) {
            text
        } else {
            AnisetteState::new()
        };
        
        if !state.is_provisioned() {
            self.provision(&mut state).await?;
            plist::to_file_xml(&config_path, &state)?;
        }
        
        let machine = state.provisioned.as_ref().ok_or(AnisetteError::AnisetteNotProvisioned)?;

        let code = machine.machine().gen_2fa_code();

        Ok(code)
    }

    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        fs::create_dir_all(&self.configuration_path)?;
        
        let config_path = self.configuration_path.join("state.plist");
        let mut state = if let Ok(text) = plist::from_file(&config_path) {
            text
        } else {
            AnisetteState::new()
        };
        
        if !state.is_provisioned() {
            self.provision(&mut state).await?;
            plist::to_file_xml(&config_path, &state)?;
        }
        let data = match self.get_headers(&state).await {
            Ok(data) => data,
            Err(err) => {
                if matches!(err, AnisetteError::AnisetteNotProvisioned) {
                    state.provisioned = None;
                    self.provision(&mut state).await?;
                    plist::to_file_xml(config_path, &mut state)?;
                    self.get_headers(&state).await?
                } else { panic!() }
            },
        };
        Ok(data.get_headers())
    }
}


