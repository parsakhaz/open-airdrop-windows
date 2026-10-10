# open-airdrop-windows

**AirDrop for Windows.** Send to and receive files from iPhones and Macs, natively from Windows — including work to
enable it on the built-in Wi-Fi card safely, with automatic restore if anything disrupts your connection.

> **Bonus:** this is part of a single "Apple interop" app that also does **[AirPlay on Windows](https://github.com/parsakhaz/open-airplay)** — receive AirPlay from your devices and mirror your screen to an Apple TV.

Open source (GPL-3.0). Windows first.

Status: the AirPlay side of the app is **working**. AirDrop on the **built-in** Wi-Fi card is **research, currently parked** — see [What's next](#whats-next) for exactly how far it got and the working path forward.

## Credits & acknowledgments

open-airdrop-windows exists because researchers and hobbyists took Apple's wireless protocols apart in public and
shared what they learned. Thank you. A visual history of that work is in
**[docs/timeline.html](docs/timeline.html)** (download it and open it in any browser).

**AWDL and AirDrop**
- **[SEEMOO Lab, TU Darmstadt](https://www.seemoo.tu-darmstadt.de/)**: Milan Stute, David Kreitschmann, Alexander
  Heinrich, Matthias Hollick and colleagues. Their paper
  [*One Billion Apples' Secret Sauce*](https://arxiv.org/abs/1808.03156) (MobiCom '18) documented Apple Wireless
  Direct Link (AWDL), the Wi-Fi link under AirDrop and AirPlay. Their open implementations
  **[OWL](https://github.com/seemoo-lab/owl)** (AWDL, in C) and **[OpenDrop](https://github.com/seemoo-lab/opendrop)**
  (AirDrop, in Python) made AirDrop possible outside Apple's platforms. See also
  [*A Billion Open Interfaces for Eve and Mallory*](https://www.usenix.org/conference/usenixsecurity19/presentation/stute)
  (USENIX Security '19) and
  [*PrivateDrop*](https://www.usenix.org/conference/usenixsecurity21/presentation/heinrich) (USENIX Security '21).
  (The project's former website, owlink.org, is no longer associated with it, so we don't link it.)
- **[omdrop-owl](https://github.com/t4t5/omdrop-owl)** by [Tristan (t4t5)](https://t4t5.com): AirDrop in both
  directions on a MediaTek MT7925, the card in the Framework 13, running OWL on the access point's own channel so
  Wi-Fi stays connected. It is the direct inspiration for this project's MT7925 work. It builds on
  [omdrop](https://github.com/brentkearney/omdrop-plugin) and
  [omdrop-awdl](https://github.com/brentkearney/omdrop-awdl) by Brent (brentkearney), and on
  [Jed Blenkhorn's OWL fork](https://github.com/jedbillyb/owl) for MediaTek cards.

**AirPlay, the other half of the app** (see [open-airplay](https://github.com/parsakhaz/open-airplay#credits--acknowledgments)
for the full list)
- **[doubletake](https://github.com/omarroth/doubletake)** by [Omar Roth](https://omar.yt): the AirPlay
  screen-mirroring sender that the app's Windows → Apple TV mirroring is ported from. LGPL-3.0-or-later.
- **[UxPlay](https://github.com/FDH2/UxPlay)**, started by [antimof](https://github.com/antimof/UxPlay) and developed
  since 2021 by FDH2, which grew out of **[RPiPlay](https://github.com/FD-/RPiPlay)** by FD- and the
  **[playfair](https://github.com/EstebanKubata/playfair)** FairPlay library by EstebanKubata: the receiver engine.
  GPL-3.0.
- **[shairport](https://github.com/abrasive/shairport)** by James Laird (2011),
  **[shairport-sync](https://github.com/mikebrady/shairport-sync)** by Mike Brady,
  **[ShairPlay](https://github.com/juhovh/shairplay)** by Juho Vähä-Herttua, and
  **[pyatv](https://github.com/postlund/pyatv)** by Pierre Ståhl: the AirPlay groundwork everything above builds on.

### Licenses, in plain language

open-airdrop-windows is licensed under the **GNU GPL-3.0**. The work it builds on is GPL-compatible: OWL and
OpenDrop are **GPL-3.0**, as are UxPlay, RPiPlay and playfair on the AirPlay side; doubletake is
**LGPL-3.0-or-later**, which is GPL-3.0 plus extra permissions, so it combines cleanly with a GPL-3.0 app. No
third-party code is vendored in this repository yet. When some is, it will keep its original copyright and license
notices and be recorded in a `NOTICE` file. This is a summary, not legal advice; the license files are what count.

### A note on FairPlay provenance

The app's AirPlay sender uses doubletake's FairPlay SAP code, which contains constants and tables needed to talk to
Apple receivers. In [doubletake issue #59](https://github.com/omarroth/doubletake/issues/59) (October 2026) a user
asked how they were derived. The author answered that an earlier version ran a carved-out piece of Apple's own
FairPlay code under an ARM64 emulator, and that the current version (since
[#14](https://github.com/omarroth/doubletake/pull/14), July 2026) is a reverse-engineered implementation containing
no Apple code other than the constants required to interoperate with first-party receivers. Only that current
implementation is ported. We haven't independently audited this, and we'd rather say so than leave it out.
FairPlay SAP authenticates a sender to a receiver; it is not FairPlay Streaming DRM and does not decrypt protected
media. None of this touches the AirDrop code.

## What's next

AirDrop needs a Wi-Fi radio that can do 802.11 **monitor mode + frame injection while staying connected** — that's what Apple Wireless Direct Link (AWDL) requires. Here's the honest state and the paths forward.

**What works today**
- [x] A tested **Wi-Fi safety net** — driver/state backup plus an independent watchdog that auto-restores your connection if a radio experiment disrupts it. Proven on real hardware (it recovered after a deliberate adapter drop).

**Built-in MediaTek MT7925 (native Windows) — parked**
This is the "no dongle *and* no reboot" dream, and it's the genuinely unsolved part. Progress so far (static analysis only, no frame sent yet):
- [x] Mapped the Windows driver's transmit path end-to-end (`WiFiCx` → the MT7925 Connac3 frame-descriptor builder) and confirmed the Linux and Windows drivers map frames into the same hardware descriptor bits.
- [x] Confirmed the private sniffer (monitor RX) path exists in the signed driver.
- [ ] **Caller-controlled raw TX** — actually injecting an AWDL frame from user space. *Not achieved.*
- [ ] **Associated monitor RX** — capturing while connected. *Not achieved.*
- [ ] Fallback if the stock driver blocks us: a replacement/filter miniport (larger effort).

Why this is slow: on Linux the `mt7925e` driver *exposes* monitor + injection, so [omdrop-owl](https://github.com/t4t5/omdrop-owl) just uses it. The Windows driver hides it, so this is a reverse-engineering project — there is no doubletake-style head start for the radio.

**The fast path that actually works (no reboot)**
- [ ] A **cheap USB Wi-Fi dongle (~$20)** passed into **WSL2** (`usbipd`), running the Linux `mt76` driver + OWL + omdrop — the omdrop-owl approach, hosted on Windows. Days, not weeks. (WSL2 can't reach the built-in PCIe card, only USB devices — which is exactly why the built-in route is hard.)

**Then**
- [ ] Fold a working AirDrop send/receive flow into the shared app UI, alongside AirPlay.

## License

[GPL-3.0](LICENSE). Not affiliated with or endorsed by Apple. "AirDrop" is a trademark of Apple Inc.
