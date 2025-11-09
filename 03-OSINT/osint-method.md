# OSINT Methodology

## OpSec & Operational Security

> [!CAUTION]
> **Critical OPSEC Reminder:** Every action leaves digital traces. Maintain operational security throughout your investigation to protect yourself, your sources, and your organization.

### Create a Sock Puppet

- Fake account that cannot be linked to you
- Build a posting history (post stuff, etc.)
- Resources
  - [Effective Sock Puppets](https://medium.com/@unseeable06/creating-an-effective-sock-puppet-for-your-osint-investigation-95fdbb8b075a)
  - [Ultimate Guide to Sock Puppets](https://osintteam.blog/the-ultimate-guide-to-sockpuppets-in-osint-how-to-create-and-utilize-them-effectively-d088c2ed6e36)
  - [Fake Name Generator](https://www.fakenamegenerator.com/)
  - [This Person does not Exist](https://thispersondoesnotexist.com/)
  - Use separate browser profiles or isolation tools (e.g., **Firefox Multi-Account Containers**) for any sock-puppet activity.
  - Acquire disposable VoIP/SMS numbers (e.g., **Burner**, **Silent Link**) to satisfy platform verification without exposing real phone numbers.
  - Audit every browser extension before installation; supply-chain attacks on popular add-ons have targeted investigators since 2024.
  - Use dedicated browser profiles/containers per case and persona; avoid logging into personal accounts.
  - Prefer hardware-backed passkeys for critical accounts; store recovery codes offline.
  - Maintain a minimal chain-of-custody: timestamp actions, hash key artifacts, and record tool versions per case.

### Advanced Sock Puppet Strategy (2024-2025)

**Persona Development:**
1. **Identity creation**:
   - Generate name, DOB, location using FakeNameGenerator
   - Create AI-generated profile photo with thispersondoesnotexist.com
   - Establish consistent backstory (education, work history, interests)
   - Document persona details in encrypted password manager

2. **Digital footprint aging**:
   - Create accounts 3-6 months before investigation
   - Post regular, mundane content (reposts, likes, comments)
   - Establish realistic activity patterns (timezone-appropriate posting)
   - Build follower/following ratios that match authentic users

3. **Technical isolation**:
   - Dedicated hardware (burner laptop/phone) or VM per critical persona
   - Unique email per platform (ProtonMail, Tutanota, or disposable services)
   - VoIP numbers via Hushed, Burner, TextNow, MySudo
   - Payment method isolation: prepaid cards, virtual cards (Privacy.com)
   - Separate VPN/proxy chain per persona

4. **Platform-specific considerations**:
   - **LinkedIn**: Complete profile, realistic job history, endorsements
   - **Twitter/X**: Bio, banner, pinned tweet; avoid suspicious burst activity
   - **Instagram**: Post photos (not stolen; use AI-generated or stock); Stories
   - **TikTok**: Watch videos in persona's niche; like/comment before posting
   - **Facebook**: Friends, groups, check-ins (very aggressive detection)
   - **Bluesky**: Gradual follower building; engage with starter packs
   - **Threads**: Link to aged Instagram account for credibility

> [!WARNING]
> Platform AI detection is increasingly sophisticated. LinkedIn, Facebook, and Instagram use behavioral analysis, device fingerprinting, and cross-platform correlation to detect fake accounts. Expect account bans if patterns are suspicious.

### Browser Isolation & Fingerprinting Countermeasures

**Multi-layer isolation:**
- **Level 1 (Basic)**: Separate browser profiles per investigation
- **Level 2 (Standard)**: Firefox Multi-Account Containers or Chrome profile switching
- **Level 3 (Enhanced)**: Mullvad Browser, Brave with hardened settings
- **Level 4 (High-risk)**: Whonix VM + Tor Browser
- **Level 5 (Maximum)**: Tails OS on dedicated hardware

**Fingerprinting mitigation:**
- Browser extensions: Canvas Defender, AudioContext Fingerprint Defender, WebGL Fingerprint Defender
- Resist browser fingerprinting (Firefox `privacy.resistFingerprinting = true`)
- Disable WebRTC (prevents IP leaks even through VPN)
- Use Chameleon or similar to randomize user agent, timezone, screen resolution
- Test fingerprinting: [AmIUnique](https://amiunique.org/), [BrowserLeaks](https://browserleaks.com/)

**Pitfalls to avoid:**
- Browser extensions themselves fingerprint you; minimize extension count
- Too-unique fingerprints are suspicious; blend with common configurations
- Don't mix personal and investigative browsing in same session/profile
- Clear cookies/cache between personas; consider Cookie AutoDelete

### Network Anonymity & VPN/Proxy Strategy

**VPN selection criteria:**
- No-logs policy (audited: Mullvad, IVPN, ProtonVPN)
- Jurisdiction outside Five/Nine/Fourteen Eyes
- Accept anonymous payment (crypto, cash)
- WireGuard or OpenVPN support
- Kill switch and DNS leak protection

**Proxy chaining:**
```bash
# ProxyChains configuration example
# Tor → VPN chain for enhanced anonymity
socks5 127.0.0.1 9050  # Tor
http   <VPN_IP>  <VPN_PORT>  # VPN
```

**Residential proxies for scraping:**
- BrightData, Smartproxy, Oxylabs (paid; expensive but effective)
- Rotate IPs per request to avoid rate limiting
- Match geolocation to target platform (US IPs for US platforms)

**DNS privacy:**
- Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)
- Trusted resolvers: Quad9 (9.9.9.9), Cloudflare (1.1.1.1), NextDNS
- Test DNS leaks: [DNSLeakTest](https://www.dnsleaktest.com/)

> [!NOTE]
> VPNs do not provide anonymity from state-level adversaries. They shift trust from ISP to VPN provider. For high-risk investigations, use Tor or multi-hop VPN chains.

## Cryptocurrency Investigation

### Transaction Analysis

- Track transaction flows between wallets
- Identify clusters of related addresses
- Monitor large transfers and whale activity
- Use block explorers to trace fund movements
- Tools:
  - Cielo: Multi-chain wallet tracking (EVM, Bitcoin, Solana, Tron)
  - TRM: Create relationship graphs for addresses/transactions
  - Arkham: Multichain explorer with entity labels, graph creation, and alerts
  - MetaSleuth: Transaction visualization for retail users
  - Range: CCTP bridge explorer
  - Socketscan: EVM bridge explorer
  - Pulsy: Bridge explorer aggregator
  - Chainalysis: **Horizon 2.0** cross-chain tracing suite (paid)
  - Elliptic: **Lens** visual link explorer (launched Dec 2024)
  - Most compliance suites now provide **real-time bridge-risk scoring** dashboards (e.g., TRM, Chainalysis)

#### Layer 2 / Rollup Analysis

**Understanding L2 Architecture:**
- **Optimistic Rollups** (Arbitrum, Optimism, Base):
  - Transactions bundled in batches and posted to L1
  - 7-day challenge period before finality
  - L1 calldata can be decoded to reconstruct L2 state
  - Use L2-specific explorers (Arbiscan, Optimistic Etherscan)

- **Zero-Knowledge Rollups** (zkSync Era, Polygon zkEVM, Scroll):
  - Transaction details hidden; only validity proofs posted to L1
  - Privacy by default; cannot reconstruct individual transactions from L1
  - Must use L2 explorer (zkSync Explorer, Polygon zkEVM Explorer)
  - Bridge events (deposits/withdrawals) visible on L1

- **StarkNet** (STARK-based):
  - Cairo VM architecture; different address derivation
  - Use Voyager or StarkScan explorers
  - Transaction tracing limited without knowledge of L2 addresses

**Layer 2 Investigation Workflow:**
1. **Identify L2 usage**: Check L1 address for bridge deposits (e.g., Arbitrum Bridge, Optimism Gateway)
2. **Extract L2 address**: L2 addresses may differ from L1; derive or observe from bridge events
3. **L2-native analysis**: Use L2 explorer to trace transactions within rollup
4. **Bridge hopping**: Track funds moving between L2s via bridges (Hop, Across, Stargate)
5. **Clustering**: Look for deposit/withdrawal patterns that suggest common ownership
6. **Timing analysis**: Small time gaps between deposit/withdrawal can indicate automated bridging

**Challenges:**
- **zkSync Era / Polygon zkEVM**: Zero-knowledge proofs hide transaction details on L2; only deposit/withdrawal bridge events visible on L1. Use [zkSync Era Block Explorer](https://explorer.zksync.io/) and [PolygonScan zkEVM](https://zkevm.polygonscan.com/).
- **Arbitrum / Optimism**: Transactions batched and compressed; L2 state reconstructed from L1 calldata. Use [Arbiscan](https://arbiscan.io/) and [Optimistic Etherscan](https://optimistic.etherscan.io/). Check [L2Beat](https://l2beat.com/) for risk framework and technology stack.
- **Privacy protocols on L2**:
  - Aztec Network: Programmable privacy with noir circuits; limited block explorer visibility.
  - Railgun: Privacy system for DeFi on Ethereum/Polygon/BSC; shielded pools obscure sender/receiver/amount.
  - Privacy Pools: Proposed Tornado Cash successor with association sets; not yet deployed at scale.
- **Bridge mixers** (Hop Protocol, Across, Stargate) create synthetic liquidity pools that break direct tracing; funds enter/exit via pool swaps.
- Cross-rollup transfers further obfuscate trails; requires tracking via bridge contracts and relayer infrastructure.
- Many L2s lack mature analytics tools; explorers show transactions but relationship graphs are sparse.

**Methodology:**
- Start with L1 bridge events (deposits/withdrawals); these anchor L2 activity to known addresses.
- Use L2-specific explorers to trace activity within the rollup.
- For privacy protocols, focus on timing analysis, deposit/withdrawal clustering, and off-chain metadata (transaction memos, Tornado Cash-style notes).

#### DeFi Investigation Techniques

**Uniswap V3 Liquidity Positions:**
- LP positions are NFTs (ERC-721); track ownership via NFT transfers
- Use Revert Finance to analyze position profitability and fee earnings
- Concentrated liquidity ranges reveal price expectations and sophisticated strategies

**Aave/Compound Lending:**
- Track collateral deposits and borrow events
- Flash loan detection: borrow and repay in same transaction
- Identify liquidation events and MEV extraction

**DEX Aggregators (1inch, Cowswap):**
- Transactions route through multiple DEXs; trace full path
- Off-chain order matching (Cowswap) hides intermediate steps
- Use Tenderly to simulate and debug complex transactions

**MEV & Sandwich Attack Detection:**
- Use EigenPhi or Jito (Solana) to identify MEV transactions
- Sandwich attacks: victim transaction surrounded by attacker buy/sell
- Track MEV bot addresses via repeated sandwich patterns

**Yield Farming & Staking:**
- Track token approvals for staking contracts
- Monitor reward claim transactions
- Identify protocol migration patterns (e.g., Curve → Convex)

#### Cautions (bridges and heuristics)

- Bridges/mixers/wrappers introduce mint/burn semantics; avoid assuming 1:1 flows without on-chain proofs.
- MEV/sandwich and aggregator paths can create false "direct" trails; validate with multiple datasets.
- Cross-label sanity: vendor labels can disagree; treat labels as hypotheses, not ground truth.
- **L2 finality**: Optimistic rollups have 7-day challenge periods; zkRollups finalize faster but proofs can be batched/delayed.

### Wallet Profiling

- Analyze wallet age and activity patterns
- Check for connections to known entities
- Monitor balance changes over time
- Identify associated exchange accounts

**Advanced Wallet Profiling (2024-2025):**
1. **Age analysis**: First transaction date, account creation pattern
2. **Activity clustering**: Time-of-day patterns (timezone hints), transaction frequency
3. **Gas price behavior**: Consistent gas price choices indicate automation vs. manual
4. **Nonce gaps**: Missing nonces suggest transaction cancellations (front-running attempts)
5. **Token diversity**: Number of different tokens held (retail vs. whale/fund indicators)
6. **Smart contract interactions**: DeFi usage, NFT minting, governance participation
7. **Funding source**: First incoming transaction (exchange, mixer, bridge, faucet)
8. **ENS domains**: Registered Ethereum Name Service domains linked to address
9. **On-chain labels**: Arkham, Nansen, Etherscan verified labels

**Example Workflow:**
```
1. Check address age: Etherscan "First Txn" field
2. Analyze transaction frequency: Dune Analytics query or manual review
3. Identify funding source: Trace first incoming transaction
4. Check for exchange deposits: Large outgoing transactions to known CEX addresses
5. Review token holdings: Etherscan "Token" tab
6. Identify smart contract interactions: Filter transactions by "Contract" type
7. Check for ENS/labels: Etherscan "Name Tag" or Arkham labels
8. Visualize flow: MetaSleuth or TRM graph
```

### Exchange Investigation

- Track deposits/withdrawals
- Monitor trading patterns
- Identify linked accounts
- Check for regulatory compliance

**Exchange OSINT Techniques:**
1. **Deposit address clustering**: CEX deposit addresses are often rotated; cluster by common withdrawal destination
2. **KYC data correlation**: If leaked exchange KYC data is available, correlate addresses
3. **Withdrawal patterns**: Large withdrawals to same external address suggest single user
4. **Trading pairs**: Specialized trading (e.g., only privacy coins) indicates behavioral pattern
5. **CEX identification**: Use heuristics (OKX uses 0x-prefixed memo fields, Binance has distinct address patterns)

**CEX Address Databases:**
- [WalletExplorer](https://www.walletexplorer.com/) (Bitcoin exchange clustering)
- Arkham Intelligence entity labels
- Nansen "Smart Money" labels (includes CEX addresses)

### NFT Investigation

- Track ownership history
- Monitor sales and transfers
- Analyze metadata and hidden content
- Identify connected wallets and marketplaces

**NFT OSINT Workflow:**
1. **Identify collection**: Contract address, collection name (OpenSea, Blur)
2. **Ownership history**: Track transfers via Etherscan or NFTScan
3. **Mint analysis**: Identify minter address, mint price, timestamp
4. **Wash trading detection**: Same addresses buying/selling to inflate floor price
5. **Metadata analysis**: IPFS CIDs, centralized vs. decentralized storage
6. **Rarity checking**: Use NFT Inspect or Icy.tools for rarity scores
7. **Revenue tracking**: Royalty payments to creator address
8. **Cross-marketplace tracking**: Same NFTs listed on multiple marketplaces

**NFT Scam Detection:**
- **Airdrop scams**: Unsolicited NFTs with malicious links in metadata
- **Rug pulls**: Creator drains liquidity or abandons project
- **Pump and dump**: Coordinated buying to inflate floor, then mass sell-off
- **Fake collections**: Impersonation of legitimate projects (check verified status)

## Image Analysis

### Contextual Analysis
- Use multiple reverse image search engines to find matches or similar images:
  - [Google Images](https://images.google.com/) / **Google Lens** (note: Google Lens now requires authentication for some features; use incognito/sock-puppet account)
  - [Yandex Images](https://yandex.com/images/)
  - [Bing Image Match](https://www.bing.com/images/)
  - [TinEye](https://tineye.com/)
  - [Copyseeker](https://copyseeker.com/) AI-based reverse-image search engine
  - [Perplexity Pro](https://www.perplexity.ai/) with image upload: AI-powered contextual analysis and web search
- Use browser extensions for quick searches:
  - [RevEye Reverse Image Search](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/kejaocbebojdmebagkjghljkeefgimdj)
  - [Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci) (multi-engine support)
- Change search terms and time to narrow down the possible results
- You can leverage [FakeNews Debunker Extension](https://chromewebstore.google.com/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe) as well
- [Picarta](https://picarta.ai/) might help with geolocation as well
- Check for embedded metadata (EXIF data) that may contain geolocation or device information:
  - [ExifTool](https://exiftool.org/)
  - [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi)
  - [EXIF Viewer Pro](https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm)

### AI-Assisted Image Analysis (2024-2025)

**LLM-based image analysis:**
- **GPT-4 Vision (ChatGPT Plus)**: Upload image, ask for landmark identification, text extraction (OCR), context analysis
- **Claude 3.5 Sonnet**: Long-context image analysis; good for comparing multiple images
- **Google Gemini 1.5 Pro**: Multi-image analysis with web search integration
- **Perplexity Pro**: Image upload + real-time web search for identification

**Prompts for geolocation:**
- "Identify the location of this image based on visible landmarks, architecture, vegetation, and signs."
- "What language is on the signs? What architectural style is visible?"
- "Based on the sun angle and shadows, what time of day and approximate latitude?"
- "What clues about the location can you extract from this image?"

**AI geolocation tools:**
- [GeoSpy](https://geospy.ai/): AI-powered geolocation from images
- [Picarta.ai](https://picarta.ai/): AI geolocation assistant
- [CarNet.ai](https://carnet.ai/): Identify car models (useful for location/era confirmation)

> [!WARNING]
> AI can hallucinate locations. Always verify AI suggestions with reverse image search, Google Maps, and manual investigation. Do not rely solely on AI output.

### Foreground Analysis
- Signs, license plates, clothing styles, vegetation, and weather conditions.
- **License plate OSINT**:
  - Identify region/country by plate format and color
  - Use blur/enhancement tools to read obscured plates
  - Cross-reference with vehicle make/model
  - Be aware of legal restrictions on plate lookup in your jurisdiction

### Background Analysis
- Landmarks, unique buildings, mountains, bodies of water, and infrastructure.
- **Landmark identification**:
  - Cross-reference with Google Earth, Bing Maps
  - Check OpenStreetMap for infrastructure details
  - Use PeakVisor for mountain identification
  - Compare with stock photography (Getty, Shutterstock, Alamy)

### Map Markings
- Flora and fauna types, which can indicate geographic regions.
- Seasonal indicators like snow, foliage, or daylight hours.
- **Flora/fauna indicators**:
  - Palm trees: tropical/subtropical regions
  - Deciduous trees: temperate regions
  - Cacti/desert vegetation: arid climates
  - Snow/ice: northern latitudes or high altitude
  - Specific species (e.g., baobab trees → Africa/Madagascar)

### Trial and Error
- Manually compare features from the image with maps and street views.
- Use platforms like `Google Street View`, `Bing Streetside`, and `Yandex Panorama` to virtually explore locations.
- Employ [Overpass Turbo](https://overpass-turbo.eu/)
- Use Snap Map public stories for area-based context pivots.
- Consider Google Earth Studio for stabilized timelapse and bearing estimation.

### Pull Text from Image (OCR)
- you can use google or Yandex OCR to pull text from image
- you can also search that text alongside your image for better results
- Transcript extraction for video (YouTube): fetch captions to improve keyword and entity search.

**OCR Tools:**
- Google Lens (best for general OCR; multilingual)
- Yandex OCR (excellent for Cyrillic script)
- [EasyOCR](https://github.com/JaidedAI/EasyOCR): Python library; supports 80+ languages
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract): Open-source; command-line
- GPT-4 Vision, Claude, Gemini: Upload image and request text extraction

**OCR Workflow:**
1. Extract text using multiple OCR engines (reduces errors)
2. Translate if necessary (Google Translate, DeepL)
3. Search extracted text in quotes for exact matches
4. Combine text search with reverse image search for better context

### Image Forensics

- Analyze images for signs of manipulation or to uncover hidden details.
- Tools:
  - [Forensically](https://29a.ch/photo-forensics/)
  - [FotoForensics](http://fotoforensics.com/)
  - [Bellingcat Photo Checker](https://photo-checker.bellingcat.com/)
  - [Sensity AI Deepfake Monitor](https://platform.sensity.ai/)
  - [Exposing.ai](https://exposing.ai/) facial-dataset search
  - C2PA verification: [Adobe Content Credentials Verify](https://verify.contentauthenticity.org/) and `c2patool`
- Techniques:
  - Error Level Analysis (ELA)
  - Metadata examination
  - Clone detection
  - Noise analysis

**Advanced Image Forensics (2024-2025):**

**Error Level Analysis (ELA):**
- Detects areas of different compression levels (indicates editing)
- Use FotoForensics or Forensically
- Uniform ELA = likely original; varied ELA = likely edited

**Clone detection:**
- Identifies copy-paste regions within image
- Forensically "Clone Detection" tool
- Common in image manipulation to hide/duplicate objects

**Noise analysis:**
- Consistent noise = likely original camera output
- Inconsistent noise = likely edited/composited
- Use Forensically "Noise Analysis" tool

**Deepfake detection:**
- Sensity AI, Reality Defender, TrueMedia
- Look for: inconsistent lighting, unnatural eye movement, temporal inconsistencies
- Cross-reference with known authentic images of subject

**C2PA Content Credentials:**
- C2PA embeds cryptographic provenance in media files
- Verify via Adobe Content Credentials or c2patool
- Indicates camera/software used, editing history, AI generation
- **Limitation**: Only works if creator embeds C2PA data

### Mountain Geolocation

- Use tools to identify mountain peaks and match them with the image.
- Tools:
  - [PeakVisor](https://peakvisor.com/)
  - [Peakfinder](https://www.peakfinder.org/)
  - [PeakLens](https://peaklens.com/) AR mountain identifier
- Methodology:
  - Align the silhouette of mountains in the image with the 3D models in the tools.
  - Adjust parameters like viewing angle and elevation.

**Advanced Mountain Geolocation:**
1. **Identify distinctive peaks**: Look for unique shapes, snow patterns, ridgelines
2. **Estimate viewing angle**: Horizon line, observer elevation
3. **Use PeakVisor**: AR mode aligns phone camera with mountain models in real-time
4. **Cross-reference with maps**: Google Earth 3D terrain, topographic maps
5. **Shadow analysis**: Sun position narrows down time/date and confirms location
6. **Vegetation line**: Tree line elevation varies by region (helps confirm latitude/climate)

### Fire Identification

- Identify fires, deforestation, or environmental changes.
- Tools:
  - [NASA FIRMS](https://earthdata.nasa.gov/earth-observation-data/near-real-time/firms)
  - [Sentinel Hub Playground](https://apps.sentinel-hub.com/sentinel-playground/)
  - [Global Forest Watch](https://www.globalforestwatch.org/)
  - [Copernicus EFFIS](https://effis.jrc.ec.europa.eu/) EU wildfire monitoring portal

**Fire OSINT Workflow:**
1. Identify approximate location from image/video
2. Check NASA FIRMS for active fire detections (past 24h/7d/year)
3. Overlay FIRMS data on Google Earth
4. Use Sentinel Hub for satellite imagery before/after fire
5. Check local news for corroboration
6. Monitor social media for eyewitness accounts (geotag search)

### Track and Find Planes

- Use [Apollo Hunter](https://imagehunter.apollomapping.com/) to find exact satellite image time
- Then use [FlightRadar](https://www.flightradar24.com/) to track that plane that you found
- Verify the size and plane features
- [ADS-B Exchange](https://www.adsbexchange.com/) – unfiltered global flight data

**Flight OSINT Workflow:**
1. **Identify aircraft type**: Livery, engine count, wing shape (use Planespotters)
2. **Extract registration**: Tail number from image (if visible)
3. **Determine flight path**: Direction, altitude clues (contrails, angle)
4. **Time correlation**: Match satellite imagery timestamp with FlightRadar historical data
5. **Cross-reference**: ADS-B Exchange for unfiltered data (includes military/private)
6. **Verify**: Check Planespotters for aircraft history, operator, routes

**Advanced Techniques:**
- **Contrail analysis**: Contrails form at specific altitudes/temperatures; use weather data
- **Shadow length**: Estimate aircraft altitude from shadow on ground
- **Audio analysis**: Engine sound can identify aircraft type
- **Flight path prediction**: Use FlightAware/FlightRadar to predict future routes

## Video Analysis

### Find Context

- Signs, banners, and billboards.
- Architectural styles and building materials.
- Road markings and traffic signs.
- License plates
- Clothing styles and local customs.
- Search for video snippets on platforms like YouTube, Twitter, or TikTok.

**Video Context Extraction:**
1. **Frame extraction**: Use FFmpeg to extract keyframes
   ```bash
   ffmpeg -i video.mp4 -vf "select=eq(n\,0)" -vsync vfr frame_%04d.png
   ```
2. **Reverse image search**: Each keyframe via Google/Yandex/TinEye
3. **OCR text extraction**: Pull text from signs, banners, screens in video
4. **Audio analysis**: Language, accents, background sounds
5. **Platform metadata**: YouTube Data Viewer, InVID extension

### Metadata Extraction

- [YouTube Data Viewer](https://citizenevidence.amnestyusa.org/)
- ExifTool: Extract metadata from downloaded video files.

**Video Metadata Fields:**
- Upload timestamp (YouTube Data Viewer)
- Geolocation tags (if enabled)
- Camera make/model (for downloaded files)
- Frame rate, resolution, codec (technical indicators)
- Author/uploader information

### Platform-Specific Techniques

#### TikTok and Instagram
- APIs change often; prefer platform exports when available
- Sample cadence: 1–4 h for fast-moving topics; keep a fixed persona and capture logs
- Analyze user profiles for location tags; examine comments and hashtags for clues

**TikTok Investigation:**
1. **Username search**: TikTok Scraper, Tokboard
2. **Hashtag monitoring**: Track challenge participation, trending topics
3. **Sound/audio analysis**: Identify coordinated posting (same audio = organized campaign)
4. **Video metadata**: Posting time (timezone hints), location tags (if enabled)
5. **Comment analysis**: Identify collaborators, audience sentiment
6. **Archive immediately**: TikTok videos can be deleted; use SnapTik or TikTok Downloader

**Instagram Reels Investigation:**
- Use Instagram OSINT tools (same infrastructure as main Instagram)
- Cross-reference Reels with Stories, Posts for timeline reconstruction
- Check tagged locations, @mentions for network analysis

#### Bluesky AT Protocol
- Resolve handles via `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=<handle>` to get DID
- Extract full identity document: `https://plc.directory/<did>` (returns PLC operations, handle history, PDS endpoint)
- Real-time firehose: Use [Firesky](https://firesky.tv/) for live keyword/hashtag monitoring across entire network
- Analytics: [SkyView](https://bsky.jazco.dev/) for follower graphs, post engagement, network analysis
- Archive early: AT Protocol allows post deletion and handle migration; capture DIDs and post CIDs
- Labelers and moderation: Check user's selected labelers (affects content visibility); different from centralized moderation
- PDS (Personal Data Server): Users can self-host; identify via DID document to understand data custody

**Bluesky Investigation Workflow:**
1. Identify handle (e.g., @user.bsky.social)
2. Resolve to DID: `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=user.bsky.social`
3. Query PLC directory: `https://plc.directory/<did>` → returns DID document with PDS, handle history, keys
4. Check handle history: Has user changed handles? (indicates evasion or rebrand)
5. Identify PDS: `pds` field in DID document (self-hosted vs. bsky.social)
6. Monitor firehose: Firesky keyword alerts for real-time activity
7. Network analysis: SkyView for follower/following graphs
8. Archive posts: Capture DIDs and CIDs (Content Identifiers) immediately

#### Mastodon / Fediverse
- Instance matters: `@user@mastodon.social` vs `@user@infosec.exchange` - different jurisdictions, moderation policies, logging practices
- WebFinger for discovery: `https://<instance>/.well-known/webfinger?resource=acct:<user>@<instance>` returns ActivityPub actor URL
- Cross-instance search: [FediSearch](https://fedisearch.skorpil.cz/) aggregates public posts; not all instances are indexed
- Instance enumeration: [Fediverse Observer](https://fediverse.observer/), [Fediverse.party](https://fediverse.party/) for instance lists, stats, software versions
- Graph analysis: Follower/following lists are public by default; export via API for network mapping
- Privacy considerations: Some instances (e.g., Pixelfed, PeerTube) federate differently; check instance software type
- Archive via API: ActivityPub objects are JSON-LD; capture `id`, `published`, `content`, `attributedTo` fields
- Deleted content: Federation is asynchronous; deletions may not propagate immediately; check caches and relay instances

**Mastodon Investigation Workflow:**
1. Identify full handle: `@user@instance.social`
2. Query WebFinger: `https://instance.social/.well-known/webfinger?resource=acct:user@instance.social`
3. Extract ActivityPub actor URL from WebFinger response
4. Fetch actor profile: `https://instance.social/users/<user>` (returns JSON with profile, public key, endpoints)
5. Enumerate followers/following: API endpoints (if public)
6. Search posts: FediSearch or instance-specific search (if enabled)
7. Check instance info: Fediverse Observer for software type, version, admin contacts
8. Map network: Export follower graph; identify cross-instance communities
9. Archive posts: Capture ActivityPub JSON objects (including `id`, `published`, `content`)

### Auditory Clues

- Languages or dialects spoken.
- Background noises (train horns, call to prayer, wildlife).
- Tools:
  - [Audacity](https://www.audacityteam.org/): Audio editing software
  - [Sonic Visualiser](https://www.sonicvisualiser.org/): Visualize audio data
  - [SoundCMD](https://soundcmd.com/) crowd-sourced sound-matching engine
- Methodology:
  - Create spectrograms to identify unique sound patterns.
  - Use **Shazam** or **SoundHound** to identify music tracks.

**Advanced Audio Analysis:**
1. **Language identification**: Identify language/dialect (hints at location)
2. **Background sounds**:
   - Sirens (emergency vehicle patterns vary by country)
   - Church bells, mosque call to prayer (religious/cultural indicators)
   - Train/subway sounds (specific to transit systems)
   - Wildlife (birds, insects specific to regions)
3. **Spectrogram analysis**: Use Sonic Visualiser or Audacity
   - Identify specific frequencies (e.g., power line hum = 50Hz EU, 60Hz US)
4. **Music identification**: Shazam, SoundHound, or ACRCloud
   - Music can narrow down cultural context, era, regional popularity
5. **Voice analysis**: Accent, dialect, linguistic markers
6. **Metadata**: Audio file metadata (recording device, software)

### Extract Key Frames

- Use tools like [FFmpeg](https://ffmpeg.org/) or [VLC Media Player](https://www.videolan.org/vlc/) to capture frames.
- Extract frames at regular intervals or when significant changes occur.
- Stitch frames together if the camera pans to create a panoramic image.
- Create a panorama if the camera pans across a scene.

**FFmpeg Frame Extraction Examples:**

Extract every Nth frame:
```bash
ffmpeg -i video.mp4 -vf "select=not(mod(n\,30))" -vsync vfr frame_%04d.png
```

Extract keyframes only:
```bash
ffmpeg -i video.mp4 -vf "select=eq(pict_type\,I)" -vsync vfr keyframe_%04d.png
```

Extract frames at specific timestamps:
```bash
ffmpeg -i video.mp4 -ss 00:01:30 -frames:v 1 frame_at_90s.png
```

Create panorama from panning video:
```bash
# Extract frames
ffmpeg -i video.mp4 -vf fps=1 frame_%04d.png
# Use Hugin or Microsoft ICE to stitch panorama
```

- Analyze frames using the same techniques as in image geolocation.
- When possible, obtain the original upload (avoid re-encodes) to retain metadata and audio clarity.
- Decode platform snowflakes (e.g., Discord, Twitter/X) to infer server-side timestamps for events.
- **Threads by Instagram**: Similar to Instagram API limitations; use web scraping or official exports where available.
- **Video stabilization**: Use FFmpeg `deshake` or Blender VSE to stabilize panning/shaky footage for better landmark identification.

## Chronolocation and Time Analysis

### Shadow Analysis

- Use shadows to estimate the time of day and date when the image or video was captured.
- Methodology:
  - Determine the length and direction of shadows in the image.
  - Identify objects casting the shadows (e.g., poles, buildings).
- Calculate Sun Position:
  - Use the object's height and shadow length to calculate the solar elevation angle.
  - Determine the azimuth (sun's compass direction).
- Tools:
  - [SunCalc](https://www.suncalc.org/)
  - [ShadeMap](https://shademap.app/) – interactive 3-D shadow simulator
  - Bellingcat **Shadow-Finder** micro-tool
    - Input location coordinates.
    - Adjust dates and times to match shadow lengths and directions.
  - **SunCalc.net**: Similar tool with additional features.
  - NOAA Solar Calculator for precise solar angles by date/time.
  - Use UTC consistently across all notes and screenshots.
  - OSM map-compare sites and EOX Cloudless layers to cross-check base imagery.

**Shadow Analysis Workflow:**
1. **Measure shadow**: Identify object casting shadow and measure shadow length
2. **Estimate object height**: Use known dimensions (e.g., standard street sign = 2-3m)
3. **Calculate solar elevation angle**: `angle = arctan(object_height / shadow_length)`
4. **Determine shadow direction**: Use compass or reference to known directions
5. **Input into SunCalc**: Enter location, adjust date/time until shadow matches
6. **Cross-verify**: Check sunrise/sunset times, seasonal patterns
7. **Time range estimation**: Shadow analysis typically gives ±1 hour accuracy

**Example:**
- Shadow length = 2m, object height = 1.5m
- Elevation angle = arctan(1.5/2) ≈ 36.87°
- Shadow points NNW (bearing ≈ 340°)
- Input location + shadow parameters into SunCalc
- Result: Approximately 10:00 AM local time, March 15

### Astronomical Calculations

- For night images, use celestial bodies to determine time and location.
- Tools:
  - [Stellarium](https://stellarium.org/): Planetarium software
  - SkyMap: Mobile app for stargazing.
  - [MoonCalc](https://www.mooncalc.org/)
- Methodology:
  - Identify visible stars, constellations, or the moon phase.
  - Use software to simulate the sky at different times and locations.
  - Match the celestial arrangement in the image to a specific date and time.

**Astronomical Chronolocation Workflow:**
1. **Identify celestial objects**: Stars, constellations, planets, moon
2. **Note moon phase**: Full, crescent, gibbous (narrows date range)
3. **Observe star positions**: Use Stellarium to simulate sky
4. **Adjust location**: Latitude affects visible constellations
5. **Adjust date/time**: Match celestial positions in image
6. **Cross-verify**: Check multiple stars/constellations for accuracy

**Key Celestial Markers:**
- **Polaris (North Star)**: Indicates true north in Northern Hemisphere
- **Southern Cross**: Indicates south in Southern Hemisphere
- **Orion's Belt**: Visible in winter (Northern Hemisphere), summer (Southern Hemisphere)
- **Moon phase**: Repeats every 29.5 days; use MoonCalc to identify date

### Satellite Imagery Time

- Use historical satellite imagery to determine changes over time.
- Tools:
  - **Google Earth Pro**:
    - Use the historical imagery slider to view images from different dates.
  - [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/)
    - Access Sentinel and Landsat data.
    - Create TimeLapse animations.
- Methodology:
  - Enter the location coordinates.
  - Select appropriate satellite datasets (Sentinel-2, Landsat 8).
  - Analyze changes in the environment to narrow down dates.
  - Record coordinates in WKT and hash cached tilesets for reproducibility where feasible.

**Satellite Imagery Analysis:**
1. **Identify location**: Lat/long from geolocation analysis
2. **Select satellite source**:
   - Google Earth: Historical imagery slider (Landsat, DigitalGlobe)
   - Sentinel Hub: Sentinel-2 (10m resolution, every 5 days)
   - Planet Labs: Daily imagery (paid; some free for researchers)
3. **Before/after comparison**: Identify construction, deforestation, infrastructure changes
4. **Cloud cover**: Filter for low cloud cover dates
5. **Seasonal changes**: Vegetation, snow cover, water levels
6. **Record methodology**: Document satellite source, date, coordinates, resolution

**Use Cases:**
- **Construction timeline**: When was building constructed? (compare historical imagery)
- **Event verification**: Confirm date of explosion, fire, or natural disaster
- **Environmental change**: Deforestation, urbanization, coastal erosion
- **Military analysis**: Vehicle/equipment movements, base construction

## Threat Actor Investigation

### Actor-Centric Workflow

- Scoping:
  - Define the actor hypothesis (e.g., APT28, APT29, Turla, Sandworm; APT10, APT41, Mustang Panda, Volt Typhoon).
  - Collect seed reports from CERTs and vendors; extract indicators and TTPs.
- Indicator harvesting:
  - Parse IOCs (domains, IPs, hashes, JA3/JA4, user-agents) from advisories and reports; normalize and de-duplicate.
  - Validate IOCs with passive DNS, CT logs, sandbox submissions, and open telemetry where possible.
- Infrastructure mapping:
  - Build pivots from CT logs (SANs, issuer, serials), shared hosting, name-server reuse, registrar accounts, and HTML/page fingerprints.
  - Enrich with ASN/WHOIS history, RPKI/ROA status, geolocation, and hosting provider relationships.
- Artifact profiling:
  - Extract PE/ELF metadata (PDB paths, compile timestamps, Rich headers, resources language, code-signing certs).
  - Cluster with fuzzy hashes (SSDEEP/TLSH) and identify packers/loaders; search YARA and sandboxes for near-matches.
- Social and procurement pivots:
  - Pivot on developer handles, code snippets, academic theses, job posts, and procurement records that imply capability or mandate.
- Falsification and reporting:
  - Weigh each linkage (weak/medium/strong); document alternatives; avoid single-source attribution.
  - Map TTPs to MITRE ATT&CK and cite sources with exact sections/pages.

### Advanced Threat Actor Profiling (2024-2025)

**Behavioral Analysis:**
1. **Operational hours**: Analyze attack timestamps (timezone hints)
2. **Tool reuse**: Custom malware, frameworks (Cobalt Strike, Metasploit)
3. **Targeting patterns**: Industry verticals, geopolitical targets
4. **Tradecraft evolution**: How TTPs change over time
5. **Linguistic artifacts**: Code comments, error messages, phishing lure language
6. **Opsec failures**: Exposed personal info, VPN leaks, social media activity

**Infrastructure Clustering:**
- **Domain registration patterns**: Registrar choice, WHOIS privacy, registration cadence
- **DNS infrastructure**: Nameserver reuse, shared hosting, CDN usage
- **SSL/TLS certificates**: Certificate reuse, issuer, subject patterns
- **IP geolocation**: Hosting provider, ASN, country
- **HTTP fingerprints**: Server headers, favicon hashes (mmh3), page structure

**Malware Analysis Pivots:**
- **PDB paths**: `C:\Users\<username>\Documents\...` reveals developer info
- **Compile timestamps**: Build time (can be forged; cross-reference)
- **Rich header**: Compiler version, Visual Studio environment
- **Code signing**: Stolen/legitimate certs, issuer patterns
- **String artifacts**: Unique strings, configuration data, C2 URLs

**Social/Procurement OSINT:**
- **Job postings**: Government contracts, required skills (e.g., "experience with APT29 TTPs")
- **Academic research**: University affiliations, thesis topics, publications
- **GitHub/GitLab**: Public code repos, commit history, contributor names
- **LinkedIn**: Employees of suspected entities, skill endorsements
- **Government procurement**: Contracts for offensive tools, "Red Team" services

### Attribution Discipline

- Separate capability from intent and sponsorship; avoid mirror-imaging.
- Use a rule-of-three: require at least three independent weak signals, or one strong + one weak, before asserting linkage.
- Prefer durable pivots (registrar accounts, code-signing cert reuse, build path idioms) over ephemeral ones (resolving IPs).
- Clearly mark uncertainty levels and confidence (e.g., low/medium/high) and distinguish correlation from control.

**Attribution Confidence Levels:**
- **High confidence (95%+)**: Multiple strong pivots, corroborated by multiple independent sources, durable technical indicators
- **Moderate confidence (60-95%)**: Some strong pivots, some weak signals, partial corroboration
- **Low confidence (<60%)**: Primarily weak signals, single-source claims, circumstantial evidence
- **Speculative (<30%)**: Hypothesis based on limited data; requires further investigation

**Strong vs. Weak Pivots:**
- **Strong**: Code signing cert reuse, unique PDB paths, consistent registrar accounts, distinctive malware families
- **Weak**: Shared IP hosting, common tools (Cobalt Strike, Mimikatz), generic TTPs, resolving DNS

**Falsification Checks:**
- Could this infrastructure be rented/compromised? (VPS, bulletproof hosting)
- Could this be a false flag? (planted artifacts, intentional misdirection)
- Are there alternative explanations? (cybercrime, hacktivist, insider)
- What evidence would disprove this hypothesis?

### Russia-Specific Pivots

- Corporate/people:
  - EGRUL/EGRIP extracts (official registry; captcha-gated) and Rusprofile/Kontur.Focus summaries for entities and directors.
  - Government procurement: `zakupki.gov.ru` (tenders, contractors), regional portals, and grant listings.
  - Job boards (e.g., `hh.ru`) for role requirements, tech stacks, and office locations.
- Infrastructure:
  - RU WHOIS: `whois.tcinet.ru`; check registrar accounts, nserver patterns, and RU-center usage.
  - Telegram is widely used; analyze channels, admins, cross-posts, and bot ecosystems.
- Media/platforms:
  - VKontakte, Odnoklassniki, Rutube, and regional news portals; search in Russian and transliterations.

**Russia OSINT Workflow:**
1. **Corporate registry search**: EGRUL/EGRIP via NALOG.ru or Rusprofile
2. **WHOIS analysis**: Check `.ru` domain registrations (RU-Center, Reg.ru patterns)
3. **Procurement analysis**: zakupki.gov.ru for government contracts
4. **Social media**: VK profiles, OK.ru, Telegram channels
5. **Job postings**: hh.ru, Superjob.ru (required skills, salaries, locations)
6. **Phone/address correlation**: Russian phone format +7 (XXX) XXX-XX-XX
7. **IP geolocation**: Russian ASNs (Rostelecom, MTS, Megafon)

**Key Russian Indicators:**
- Cyrillic keyboard layout artifacts in code/configs
- Russian time zones (MSK = UTC+3)
- Russian holidays (operational pauses)
- Specific tools (Zebrocy, XAgent, X-Tunnel = APT28)

### China-Specific Pivots

- Corporate/people:
  - National Enterprise Credit Info System (`gsxt.gov.cn`) for registered entities; cross-check with Tianyancha/Qichacha (paid/freemium).
  - ICP filings (`beian.miit.gov.cn`) to link domains to legal entities via Unified Social Credit Codes (USCC).
- Infrastructure:
  - CNNIC WHOIS and hosting footprints; common domestic clouds (Aliyun, Tencent Cloud, Huawei Cloud) and registrar patterns.
- Media/platforms:
  - Weibo, WeChat Official Accounts (via `weixin.sogou.com`), Zhihu, Bilibili, Douyin, Xiaohongshu; search in Chinese and Pinyin.

**China OSINT Workflow:**
1. **Corporate registry**: GSXT.gov.cn (National Enterprise Credit Information Publicity System)
2. **ICP filings**: beian.miit.gov.cn (link domains to companies via ICP license)
3. **Company databases**: Tianyancha, Qichacha (paid; deep corporate data)
4. **Social media**: Weibo, WeChat OA (via Sogou Weixin), Zhihu, Bilibili
5. **E-commerce**: Taobao, JD.com seller info (can reveal company affiliations)
6. **Phone/address**: Chinese phone format +86 1XX-XXXX-XXXX
7. **IP geolocation**: Chinese ASNs (China Telecom, China Unicom, Aliyun, Tencent)

**Key Chinese Indicators:**
- Simplified Chinese language artifacts
- Chinese time zones (CST = UTC+8)
- Chinese holidays (Spring Festival, National Day)
- Specific tools (PlugX, Poison Ivy, Cobalt Strike with Chinese modifications)
- APT naming: APT1, APT10, APT41, Mustang Panda, Stone Panda, etc.

### Infrastructure & Internet Measurement

- Map IPs to ASNs (HE BGP Toolkit, RIPEstat, BGPView); observe peering and hosting ecosystems.
- Check CT logs (crt.sh) for certificate reuse and issuance cadence; pivot on subjects/issuers/serials.
- Use URLScan and similar crawlers to capture HTML fingerprints, favicons (mmh3), and script hashes for clustering.
- Monitor DNS over time (SecurityTrails PDNS, DNSDB) for subdomain churn and staging domains.

**Infrastructure Pivoting Workflow:**
1. **IP → ASN**: Use HE BGP Toolkit or RIPEstat
2. **ASN → Prefixes**: Identify IP ranges owned by organization
3. **Shared hosting**: Check for other domains/IPs on same ASN
4. **Passive DNS**: SecurityTrails, DNSDB (historical DNS records)
5. **CT logs**: crt.sh (certificate issuance patterns)
6. **Favicon hash**: Calculate mmh3 hash of favicon; search Shodan/Censys
7. **JA3/JA4 fingerprints**: TLS client/server fingerprints
8. **HTML fingerprints**: URLScan.io, CommonCrawl

**Example:**
```
IP: 203.0.113.42
→ ASN: AS12345 (Example Hosting LLC)
→ Prefix: 203.0.113.0/24
→ Passive DNS: example-malicious.com, staging.evil.com
→ CT logs: *.evil.com certs issued 2024-01-15
→ Favicon hash: -1234567890 (matches 5 other IPs on Shodan)
→ Conclusion: Infrastructure cluster likely controlled by same actor
```

## People & Social Media Investigation

### Username Enumeration

- Tools:
  - [WhatsMyName](https://whatsmyname.app/)
  - [NameCheckup](https://namecheckup.com/)
  - [Sherlock](https://github.com/sherlock-project/sherlock)
  - [Maigret](https://github.com/soxoj/maigret)
  - [BlackBird](https://github.com/p1ngul1n0/blackbird)

**Username Enumeration Workflow:**
1. **Identify target username**: Extract from known profile, email, handle
2. **Run automated tools**: Sherlock, Maigret, BlackBird (check 500-3000+ sites)
3. **Manual verification**: Visit each result; confirm same person (profile photo, bio, post history)
4. **Timeline analysis**: Account creation dates (reveals activity timeline)
5. **Cross-platform correlation**: Same bio, profile pic, linked accounts
6. **Archive findings**: Screenshot profiles, capture URLs with timestamps

**Advanced Username Techniques:**
- **Username variations**: `user123`, `user_123`, `user.123`, `user-123`
- **Leetspeak**: `u53r`, `us3r`, `user1337`
- **Historical usernames**: Twitter/X handle changes (via Wayback Machine, Mugetsu)
- **Email permutations**: `username@gmail.com`, `username@protonmail.com`

### Profile Picture & Face Search

- Tools:
  - [PimEyes](https://pimeyes.com/)
  - [Exposing.ai](https://exposing.ai/)
  - Azure Face API (subject to compliance policies)
  - [FaceCheck.ID](https://facecheck.id/)

**Facial Recognition OSINT Workflow:**
1. **Extract face**: Crop profile picture to face only (improves accuracy)
2. **Run multiple engines**: PimEyes, FaceCheck.ID, Yandex Image Search
3. **Filter results**: Age, gender, ethnicity, location (if visible)
4. **Reverse image search**: Google/Yandex/TinEye for stolen photos
5. **Cross-reference platforms**: Match face to usernames, profiles, tagged photos
6. **Archive results**: Screenshot matches with timestamps

> [!WARNING]
> Facial recognition is legally restricted in many jurisdictions (EU GDPR Article 9, US state laws). Use ethically and only for legitimate investigations. PimEyes has been criticized for privacy violations.

### Social Graph & Content Analysis

- Tools:
  - [Maltego](https://www.maltego.com/)
  - [snscrape](https://github.com/snscrape/snscrape)
  - [SocialBlade](https://socialblade.com/)
  - Bluesky/Mastodon: use instance explorers and handle resolvers; pivot across the Fediverse

**Social Network Analysis Workflow:**
1. **Identify seed accounts**: Target user and known associates
2. **Map followers/following**: Export lists via platform APIs or scraping tools
3. **Identify clusters**: Use Maltego or Gephi to visualize network graphs
4. **Find bridge accounts**: Users connecting different clusters (information brokers)
5. **Temporal analysis**: When did relationships form? (account creation, first interaction)
6. **Content analysis**: Shared hashtags, retweets, mentions, coordinated posting
7. **Cross-platform linkage**: Same users across Twitter, Telegram, Discord, etc.

**Network Analysis Metrics:**
- **Degree centrality**: Number of connections (identifies influencers)
- **Betweenness centrality**: Users bridging clusters (information brokers)
- **Clustering coefficient**: Tight-knit groups vs. loose networks
- **Temporal patterns**: Burst activity (events, campaigns), coordinated posting

## Infrastructure OSINT

### IP & Domain Discovery

- Tools:
  - [Shodan](https://www.shodan.io/)
  - [Censys](https://censys.io/)
  - [Onyphe](https://www.onyphe.io/)
  - [DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/)

**Infrastructure Discovery Workflow:**
1. **Seed domain/IP**: Start with known malicious domain or IP
2. **Passive DNS**: SecurityTrails, DNSDB (historical DNS records)
3. **Subdomain enumeration**: Amass, Subfinder (discover subdomains)
4. **Certificate Transparency**: crt.sh (find related domains via SSL certs)
5. **Shodan/Censys**: Enumerate open ports, services, banners
6. **ASN mapping**: Identify IP ranges owned by target
7. **Shared hosting**: Find other domains on same IP (reverse IP lookup)
8. **Archive findings**: Hash cached data, record timestamps

### Certificate & Passive DNS

- Tools:
  - [crt.sh](https://crt.sh/)
  - [SecurityTrails](https://securitytrails.com/)

**Certificate Transparency Pivoting:**
1. **Search domain**: crt.sh → find all certs issued for domain
2. **Identify patterns**: Same issuer, subject, serial number
3. **SAN analysis**: Subject Alternative Names reveal related domains
4. **Issuer clustering**: Certs from same issuer/registrar
5. **Issuance timing**: Batch registrations (indicates automation)
6. **Expired certs**: Historical infrastructure no longer in use

**Passive DNS Analysis:**
1. **Historical records**: SecurityTrails, DNSDB (A, AAAA, MX, NS, TXT records)
2. **IP hopping**: Domain resolves to multiple IPs over time
3. **Fast-flux detection**: Rapid IP changes (malware C2 technique)
4. **Nameserver reuse**: Shared DNS infrastructure
5. **WHOIS history**: Track registrar, registrant changes over time

### Malware & Artifact Analysis Workflow

- Static triage:
  - Hash (SHA-256), strings, import tables, PDB path, Rich header, resources; check VT/Malpedia family hints (do not rely solely on AV labels).
- Dynamic/sandbox:
  - Execute in sandboxes (ANY.RUN, Hybrid Analysis, CAPE, Tria.ge) to collect network IOCs, mutexes, file drops, and C2 patterns.
- Clustering:
  - Use SSDEEP/TLSH and YARA matches to find related samples; compare config schemas and protocol quirks.
- Reporting:
  - Normalize IOCs (STIX 2.1 if possible), include ATT&CK technique IDs, and provide reproduction steps.

**Detailed Malware Analysis Workflow:**

**1. Static Analysis:**
```bash
# Calculate hashes
sha256sum malware.exe
ssdeep malware.exe
tlsh -f malware.exe

# Extract strings
strings malware.exe | grep -E '(http|ftp|\.dll|\.exe|C:\\)'

# Analyze PE headers
pefile malware.exe
# Check: Compile timestamp, PDB path, imports, exports, resources, Rich header

# Extract resources
ResourceHacker -open malware.exe -save resources.txt -action extract

# YARA scanning
yara -r rules/ malware.exe
```

**2. Dynamic Analysis:**
- Execute in sandbox (ANY.RUN, Hybrid Analysis, CAPE)
- Monitor: Network traffic, file writes, registry changes, process creation
- Extract: C2 IPs/domains, dropped files, persistence mechanisms

**3. Network Analysis:**
- Capture PCAP during execution
- Identify C2 protocols: HTTP(S), DNS, custom binary
- Extract: User-Agent strings, HTTP headers, POST data
- JA3/JA4 fingerprinting: TLS client/server fingerprints

**4. Code Analysis (if necessary):**
- Disassemble with IDA Pro, Ghidra, or Binary Ninja
- Identify: Encryption algorithms, obfuscation, anti-analysis techniques
- Recover: Configuration data, hardcoded IPs/domains, encryption keys

**5. Clustering & Attribution:**
- Search VirusTotal for similar samples (fuzzy hash match)
- Query Malpedia for known families
- Compare PDB paths, compile timestamps, code similarities
- Link to known threat actors via TTPs, infrastructure overlaps

### Telegram/WeChat Investigation

#### Telegram OSINT

- Telegram:
  - Use public analytics (TGStat, Telemetr, Combot) for channel growth, overlaps, and forwarding graphs.
  - Export channels with Telegram Desktop; preserve message IDs, timestamps (UTC), and media hashes.

**Telegram Investigation Workflow:**
1. **Identify target**: Channel username (e.g., `@channelname`) or user handle
2. **Channel analytics**: TGStat, Telemetr (subscriber growth, engagement, forwards)
3. **Message search**: TGStat message search (keyword, date range)
4. **Export channel**: Telegram Desktop → Export chat history (JSON, HTML)
5. **Media download**: Download images, videos, documents (hash for deduplication)
6. **Forward graph**: Identify content sources (which channels forward to target)
7. **Admin identification**: Check channel description, pinned messages
8. **Cross-platform links**: Links to Twitter, YouTube, websites
9. **Archive immediately**: Telegram messages/channels can be deleted

**Telegram Data Preservation:**
```bash
# Export Telegram channel with Telegram Desktop
# Settings → Advanced → Export Telegram data
# Select: Messages, Media, Contacts
# Format: JSON (machine-readable) or HTML (human-readable)

# Hash media files
sha256sum media/*
```

#### WeChat OSINT

- WeChat:
  - Search Official Accounts via `weixin.sogou.com`; archive articles (PNG + WARC); capture `__biz` IDs and publisher metadata.
  - Expect link rot and content takedowns—archive early.

**WeChat Investigation Workflow:**
1. **Official Account search**: weixin.sogou.com (search by name, keyword)
2. **Article archiving**: Save as PNG, WARC, PDF (content frequently deleted)
3. **Extract metadata**: `__biz` ID (unique account identifier), publish date, author
4. **QR code extraction**: WeChat accounts identified by QR code
5. **Cross-reference**: Search `__biz` ID for related accounts
6. **Monitor updates**: Use RSS feeds or monitoring tools for new posts
7. **Archive aggressively**: WeChat censorship is pervasive; content disappears quickly

## Automation & Case Management

- Tools:
  - [Hunchly](https://www.hunch.ly/) (browser evidence capture)
  - [Kasm Workspaces](https://kasmweb.com/) OSINT-ready workspace images
  - [ArchiveBox](https://archivebox.io/) – self-hosted web archiver
  - [SingleFileZ](https://github.com/gildas-lormeau/SingleFileZ)

**Case Management Best Practices:**
1. **Evidence capture**: Hunchly auto-captures all visited pages with timestamps
2. **Archiving**: ArchiveBox for automated URL archiving (HTML, PDF, WARC)
3. **Note-taking**: Obsidian, Joplin, or CaseFile for structured notes
4. **Timeline creation**: Use timeline tools (Timesketch, Plaso) for chronological analysis
5. **Evidence hashing**: SHA-256 hash all downloaded files
6. **Chain of custody**: Document who collected what, when, and how
7. **Encrypted storage**: Store sensitive evidence in VeraCrypt or LUKS containers
8. **Version control**: Use git for tracking investigation notes and changes

**OSINT Workflow Automation:**
```python
# Example: Automated Twitter monitoring with n8n
# Workflow: Monitor keyword → Extract tweets → Archive → Alert

# Components:
# 1. Twitter API node (fetch tweets matching keyword)
# 2. ArchiveBox node (archive tweet URLs)
# 3. Webhook node (send alert to Slack/Discord)
# 4. Schedule: Run every 15 minutes

# Alternative: Huginn agents for RSS monitoring, web scraping, alerting
```

## Synthetic Media Verification

- Tools:
  - [Sensity AI](https://sensity.ai/)
  - [Hive Moderation](https://hivemoderation.com/)
  - [Reality Defender](https://realitydefender.com/)
  - [TrueMedia](https://truemedia.org/)
  - [Illuminarty](https://illuminarty.ai/)

**Deepfake Detection Workflow:**
1. **Visual inspection**: Inconsistent lighting, unnatural eye movement, face-edge artifacts
2. **Temporal analysis**: Frame-by-frame inconsistencies (face morphing, glitches)
3. **Audio analysis**: Voice cloning artifacts (unnatural pitch, cadence)
4. **Metadata check**: Detect AI-generation markers (EXIF, C2PA)
5. **Reverse image search**: Find original source footage (if face-swapped)
6. **AI detection tools**: Upload to Sensity AI, Reality Defender, TrueMedia
7. **Cross-reference**: Compare with known authentic media of subject

**AI-Generated Image Indicators:**
- Inconsistent lighting/shadows
- Artifacts around edges (especially hands, teeth)
- Unnatural symmetry
- Repeated patterns (AI generalization)
- Metadata: No camera EXIF data, AI software markers

**AI-Generated Text Indicators:**
- Repetitive phrasing, filler language
- Overly formal or generic tone
- Lack of personal anecdotes or specific details
- Use GPTZero, Originality.AI for detection

> [!NOTE]
> Deepfake detection is an arms race. As detection improves, generation improves. Always verify via multiple methods and cross-reference with known authentic media.

---

**Last Updated:** 2025-01-07
**Maintained by:** Ünsal
**Repository:** Awesome-Collection/03-OSINT
