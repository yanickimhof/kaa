"""Every sentence Kaa writes about a finding, in English and French.

Findings keep their English text in the database; the API renders them in the
language you chose from ``rule_id`` plus the facts stored with the finding.
"""

from __future__ import annotations

# rule id -> {lang: (title, detail, fix)}. Placeholders come from the finding's evidence and {name}.
CATALOG: dict[str, dict[str, tuple[str, str, str]]] = {
    "KAA-NEW-DEVICE": {
        "en": ("New device joined: {name}",
               "A device that was not present at the first scan appeared on your network.",
               "If you recognise it, mark it Known. If not, change your Wi-Fi password and review your router's client list."),
        "fr": ("Nouvel appareil : {name}",
               "Un appareil absent lors du premier scan est apparu sur votre réseau.",
               "Si vous le reconnaissez, marquez-le Connu. Sinon, changez le mot de passe Wi-Fi et vérifiez la liste des clients du routeur.")},
    "KAA-FLAPPING": {
        "en": ("Unstable connection: {name}", "This device disconnected {drops_last_hour} times in the last hour.",
               "Check its power and Wi-Fi signal. Repeated reconnections can also be a sign of a failing device or of someone interfering with the network."),
        "fr": ("Connexion instable : {name}", "Cet appareil s'est déconnecté {drops_last_hour} fois en une heure.",
               "Vérifiez son alimentation et son signal Wi-Fi. Des reconnexions répétées peuvent aussi indiquer un appareil défaillant ou une interférence.")},
    "KAA-PORT-NEW": {
        "en": ("New open port on {name}", "Since Kaa first checked this device, {count} more port(s) opened: {ports}.",
               "If you did not install or enable something, turn the service off or update the device. Acknowledge it if the change is expected."),
        "fr": ("Nouveau port ouvert sur {name}", "Depuis la première vérification de cet appareil, {count} port(s) de plus sont ouverts : {ports}.",
               "Si vous n'avez rien installé ni activé, désactivez le service ou mettez l'appareil à jour. Acquittez si ce changement est attendu.")},
    "KAA-FIRMWARE-CHECK": {
        "en": ("Firmware check due: {name}", "Kaa cannot read firmware versions. It has been {days} days since you last checked this device.",
               "Open the vendor app, install any update, then press Mark as checked in the device panel."),
        "fr": ("Vérification du firmware : {name}", "Kaa ne peut pas lire les versions de firmware. Cela fait {days} jours que vous n'avez pas vérifié cet appareil.",
               "Ouvrez l'application du constructeur, installez les mises à jour, puis appuyez sur Marquer comme vérifié dans la fiche de l'appareil.")},
    "KAA-RANDOM-MAC": {
        "en": ("Private Wi-Fi address: {name}",
               "This device uses a randomised MAC address, a privacy feature of modern phones and laptops. It cannot be recognised by vendor.",
               "Mark it Known once you have identified the owner."),
        "fr": ("Adresse Wi-Fi privée : {name}",
               "Cet appareil utilise une adresse MAC aléatoire, une protection de la vie privée des téléphones et ordinateurs récents. Le constructeur n'est pas identifiable.",
               "Marquez-le Connu une fois son propriétaire identifié.")},
    "KAA-UNIDENTIFIED": {
        "en": ("Unidentified device: {name}", "Kaa could not tell what this device is from its vendor and services.",
               "Check the IP in your router, then label it so it is tracked from now on."),
        "fr": ("Appareil non identifié : {name}", "Kaa n'a pas pu déterminer ce qu'est cet appareil à partir de son constructeur et de ses services.",
               "Repérez son adresse IP dans votre routeur, puis donnez-lui un nom pour le suivre.")},
    "KAA-PORT-TELNET": {
        "en": ("Telnet is open on {name}", "Telnet sends logins in clear text and is a classic entry point for IoT malware.",
               "Turn Telnet off in the device settings. Use SSH if remote access is needed."),
        "fr": ("Telnet ouvert sur {name}", "Telnet transmet les identifiants en clair et sert souvent de porte d'entrée aux logiciels malveillants des objets connectés.",
               "Désactivez Telnet dans les réglages de l'appareil. Utilisez SSH si un accès à distance est nécessaire.")},
    "KAA-PORT-FTP": {
        "en": ("FTP is open on {name}", "FTP transmits credentials and files without encryption.",
               "Disable FTP or replace it with SFTP. Restrict access to trusted devices."),
        "fr": ("FTP ouvert sur {name}", "FTP transmet identifiants et fichiers sans chiffrement.",
               "Désactivez FTP ou remplacez-le par SFTP. Limitez l'accès aux appareils de confiance.")},
    "KAA-PORT-RDP": {
        "en": ("Remote Desktop (RDP) is open on {name}", "RDP is heavily targeted by brute force and exploits.",
               "Disable RDP if unused. Otherwise require network level authentication and a VPN."),
        "fr": ("Bureau à distance (RDP) ouvert sur {name}", "RDP est une cible fréquente des attaques par force brute et des exploits.",
               "Désactivez RDP s'il est inutile. Sinon, exigez l'authentification réseau et un VPN.")},
    "KAA-PORT-VNC": {
        "en": ("VNC screen sharing is open on {name}", "VNC is often protected by a weak password and has no encryption by default.",
               "Turn off screen sharing if unused, or set a strong password and tunnel it."),
        "fr": ("Partage d'écran VNC ouvert sur {name}", "VNC est souvent protégé par un mot de passe faible et n'est pas chiffré par défaut.",
               "Désactivez le partage d'écran s'il est inutile, ou définissez un mot de passe fort et passez par un tunnel.")},
    "KAA-PORT-RTSP": {
        "en": ("Video stream port (RTSP) is open on {name}", "Cameras exposing RTSP sometimes serve their stream without a password.",
               "Check that the stream asks for credentials and that the camera has no default password."),
        "fr": ("Port de flux vidéo (RTSP) ouvert sur {name}", "Les caméras qui exposent RTSP diffusent parfois leur flux sans mot de passe.",
               "Vérifiez que le flux demande des identifiants et que la caméra n'a pas de mot de passe par défaut.")},
    "KAA-PORT-MQTT": {
        "en": ("MQTT broker without TLS is reachable on {name}", "Plain MQTT carries data and commands in clear text, sometimes with no login.",
               "Require authentication and move to MQTT over TLS (port 8883)."),
        "fr": ("Broker MQTT sans TLS accessible sur {name}", "MQTT sans TLS transporte données et commandes en clair, parfois sans identifiant.",
               "Exigez une authentification et passez à MQTT sur TLS (port 8883).")},
    "KAA-GW-HTTP": {
        "en": ("Router admin page has no HTTPS", "The gateway serves its admin interface over plain HTTP only.",
               "Enable HTTPS for the admin interface if your router supports it."),
        "fr": ("La page d'administration du routeur n'a pas de HTTPS", "La passerelle sert son interface d'administration en HTTP simple uniquement.",
               "Activez HTTPS pour l'interface d'administration si votre routeur le permet.")},
    "KAA-UPNP-IGD": {
        "en": ("UPnP is enabled on your router", "UPnP lets any device on the network open ports to the Internet without asking you.",
               "Disable UPnP in the router settings, then forward ports manually only if something breaks."),
        "fr": ("UPnP est activé sur votre routeur", "UPnP permet à n'importe quel appareil d'ouvrir des ports vers Internet sans vous demander.",
               "Désactivez UPnP dans les réglages du routeur, puis ouvrez les ports à la main seulement si quelque chose ne fonctionne plus.")},
    "KAA-GATEWAY-MAC-CHANGED": {
        "en": ("Your router's hardware address changed",
               "The device answering as your gateway now has a different MAC address. This happens when the router is replaced, and in ARP spoofing attacks.",
               "If you did not swap your router, treat this as an attack: disconnect unknown devices and check the router. If you did, acknowledge to accept."),
        "fr": ("L'adresse matérielle de votre routeur a changé",
               "L'appareil qui répond comme passerelle a désormais une autre adresse MAC. Cela arrive quand le routeur est remplacé, et lors d'attaques par usurpation ARP.",
               "Si vous n'avez pas changé de routeur, considérez-le comme une attaque : déconnectez les appareils inconnus et vérifiez le routeur. Sinon, acquittez pour accepter.")},
    "KAA-CRITICAL-OFFLINE": {
        "en": ("Critical device offline: {name}", "This device you marked critical has been unreachable for {minutes} minutes.",
               "Check its power and network. If it is a lock or a camera, verify it physically."),
        "fr": ("Appareil critique hors ligne : {name}", "Cet appareil marqué critique est injoignable depuis {minutes} minutes.",
               "Vérifiez son alimentation et sa connexion. S'il s'agit d'une serrure ou d'une caméra, contrôlez-le sur place.")},
    "KAA-KEV-MODEL": {
        "en": ("A known exploited flaw may affect {name}",
               "CISA lists {cve} ({product}) as exploited in the wild, and it matches the model of this device (firmware: {firmware}). Kaa cannot tell whether your version is already fixed.",
               "Check the vendor's security advisory and make sure the firmware is newer than the fix. If it cannot be updated, move it to the guest network or unplug it."),
        "fr": ("Une faille activement exploitée peut concerner {name}",
               "La CISA classe {cve} ({product}) comme exploitée dans la nature, et elle correspond au modèle de cet appareil (firmware : {firmware}). Kaa ne peut pas savoir si votre version est déjà corrigée.",
               "Consultez l'avis de sécurité du constructeur et vérifiez que le firmware est plus récent que le correctif. S'il ne peut pas être mis à jour, passez-le sur le réseau invité ou débranchez-le.")},
    "KAA-WIFI-WEAK": {
        "en": ("Your Wi-Fi uses weak encryption ({mode})", "The network this Mac is connected to uses {mode}. Anyone nearby can break this in minutes.",
               "In the router settings, switch the Wi-Fi security to WPA2 or WPA3, then reconnect your devices."),
        "fr": ("Votre Wi-Fi utilise un chiffrement faible ({mode})", "Le réseau auquel ce Mac est connecté utilise {mode}. Quelqu'un à proximité peut le casser en quelques minutes.",
               "Dans les réglages du routeur, passez la sécurité Wi-Fi en WPA2 ou WPA3, puis reconnectez vos appareils.")},
    "KAA-NO-SEGMENTATION": {
        "en": ("Connected objects share the network with your personal devices",
               "{iot} connected objects ({names}) sit on the same network as {people} computers, phones or tablets. If one of them is compromised, it can see the others.",
               "Put cameras, locks and appliances on the guest network of your router, and mark them as guest in Kaa."),
        "fr": ("Les objets connectés partagent le réseau avec vos appareils personnels",
               "{iot} objets connectés ({names}) sont sur le même réseau que {people} ordinateurs, téléphones ou tablettes. Si l'un d'eux est compromis, il peut voir les autres.",
               "Placez caméras, serrures et électroménager sur le réseau invité du routeur, et marquez-les comme invités dans Kaa.")},
    "KAA-EXPOSED-PORTS": {
        "en": ("{count} port(s) of your Internet connection are reachable from outside", "Shodan's last crawl of your public address saw these ports open: {ports}. Anyone on the Internet can try them.",
               "Close what you do not use: disable UPnP and remove port forwards in the router settings. If a service must stay open, protect it with strong credentials and updates."),
        "fr": ("{count} port(s) de votre connexion Internet sont joignables de l'extérieur", "Le dernier passage de Shodan sur votre adresse publique a vu ces ports ouverts : {ports}. N'importe qui sur Internet peut les tester.",
               "Fermez ce que vous n'utilisez pas : désactivez UPnP et supprimez les redirections de ports dans le routeur. Si un service doit rester ouvert, protégez-le avec des identifiants forts et des mises à jour.")},
    "KAA-EXPOSED-VULNS": {
        "en": ("Known vulnerabilities are attached to your public address", "Shodan associates {count} known vulnerabilities with what it sees on your address: {cves}.",
               "Find which device answers on that address (a port forward or UPnP mapping) and update or remove it."),
        "fr": ("Des failles connues sont associées à votre adresse publique", "Shodan associe {count} failles connues à ce qu'il voit sur votre adresse : {cves}.",
               "Trouvez quel appareil répond sur cette adresse (redirection de port ou UPnP) et mettez-le à jour ou retirez-le.")},
    "KAA-CLOUD-BATTERY": {
        "en": ("Low battery on {count} radio device(s)", "Reported by Tado or Netatmo: {names}.",
               "Replace the batteries soon. A dead sensor or valve silently stops protecting or heating."),
        "fr": ("Pile faible sur {count} appareil(s) radio", "Signalé par Tado ou Netatmo : {names}.",
               "Remplacez les piles prochainement. Un capteur ou une vanne à plat cesse de fonctionner sans prévenir.")},
    "KAA-CLOUD-OFFLINE": {
        "en": ("{count} radio device(s) unreachable", "Tado or Netatmo reports no contact with: {names}.",
               "Check the batteries and the distance to the bridge or gateway. If it persists, re-pair the device."),
        "fr": ("{count} appareil(s) radio injoignable(s)", "Tado ou Netatmo ne reçoit plus de signal de : {names}.",
               "Vérifiez les piles et la distance au pont ou à la passerelle. Si cela persiste, réassociez l'appareil.")},
    "KAA-LOCK-EXPOSED": {
        "en": ("Smart lock exposes a network service: {name}", "A lock should not answer on network ports; this widens its attack surface.",
               "Update its firmware and look in its settings for a local web interface or API you can turn off."),
        "fr": ("Serrure connectée avec service réseau exposé : {name}", "Une serrure ne devrait pas répondre sur des ports réseau : cela élargit sa surface d'attaque.",
               "Mettez à jour son firmware et cherchez dans ses réglages une interface web locale ou une API à désactiver.")},
    "KAA-CAMERA-HTTP": {
        "en": ("Camera web page without HTTPS: {name}", "Its web interface answers in clear HTTP, so a password typed on your network can be read.",
               "Enable HTTPS in the camera settings, or only use its official app."),
        "fr": ("Page web de caméra sans HTTPS : {name}", "Son interface web répond en HTTP clair : un mot de passe saisi sur votre réseau peut être lu.",
               "Activez HTTPS dans les réglages de la caméra, ou n'utilisez que son application officielle.")},
    "KAA-TLS-EXPIRED": {
        "en": ("Expired certificate on {name}", "Its HTTPS certificate expired on {expired}. Browsers will warn and the device is probably not maintained.",
               "Renew the certificate if you manage it, or check for a firmware update."),
        "fr": ("Certificat expiré sur {name}", "Son certificat HTTPS a expiré le {expired}. Les navigateurs afficheront un avertissement et l'appareil n'est probablement plus entretenu.",
               "Renouvelez le certificat si vous le gérez, ou cherchez une mise à jour du firmware.")},
    "KAA-FTP-ANON": {
        "en": ("Anonymous FTP login accepted on {name}", "Anyone on your network can open this FTP server without a password.",
               "Disable anonymous access, or turn FTP off."),
        "fr": ("Connexion FTP anonyme acceptée sur {name}", "N'importe qui sur votre réseau peut ouvrir ce serveur FTP sans mot de passe.",
               "Désactivez l'accès anonyme, ou désactivez FTP.")},
}


def render(lang: str, rule_id: str, name: str, evidence: dict) -> tuple[str, str, str] | None:
    entry = CATALOG.get(rule_id)
    if not entry:
        return None
    title, detail, fix = entry.get(lang) or entry["en"]
    params = {"name": name, **{k: v for k, v in (evidence or {}).items() if isinstance(v, (str, int, float))}}
    try:
        return title.format(**params), detail.format(**params), fix.format(**params)
    except (KeyError, IndexError):
        return entry["en"]
