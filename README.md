# 🚀 VpnEndpointInspector


**Développé par: Ayi NEDJIMI Consultants**

## 📋 Description

VpnEndpointInspector est un outil d'audit des configurations VPN et RRAS (Routing and Remote Access Service) sur Windows. Il énumère et analyse :

- **Connexions VPN clientes** configurées via RAS (Remote Access Service)
- **Serveur RRAS** (si installé et configuré)
- Protocoles VPN utilisés (PPTP, L2TP/IPSec, SSTP, IKEv2)
- Méthodes d'authentification (PAP, CHAP, MS-CHAP, MS-CHAPv2, EAP)
- Ports standards associés
- Configurations de sécurité (chiffrement, authentification)

L'outil identifie les configurations faibles ou obsolètes pouvant représenter un risque de sécurité.


## 📌 Prérequis

- Windows 10/11 ou Windows Server 2016+
- Visual Studio 2019+ avec Build Tools (cl.exe)
- Droits administrateur pour accéder à certaines configurations RRAS
- Connexions VPN configurées (pour les tester)


## Compilation

### Option 1 : Utiliser le script batch
```batch
go.bat
```

### Option 2 : Ligne de commande manuelle
```batch
cl.exe /EHsc /W4 /std:c++17 /Fe:VpnEndpointInspector.exe VpnEndpointInspector.cpp /link rasapi32.lib advapi32.lib comctl32.lib user32.lib gdi32.lib
```


## 🚀 Utilisation

1. Lancer l'exécutable `VpnEndpointInspector.exe` (de préférence en administrateur)
2. Cliquer sur **Scanner les Configurations VPN/RRAS**
3. Analyser les résultats dans la liste
4. Optionnel : Exporter les résultats en CSV


## Interface

### Boutons
- **Scanner les Configurations VPN/RRAS** : Lance l'énumération des connexions VPN et la vérification RRAS
- **Exporter CSV** : Exporte les résultats au format CSV UTF-8 avec BOM

### Liste des résultats
Colonnes affichées :
- **Nom de Connexion** : Nom de la connexion VPN ou "[RRAS Service]" pour le serveur
- **Type** : Type de VPN (PPTP, L2TP/IPSec, SSTP, IKEv2, Serveur RRAS)
- **Serveur** : Adresse du serveur VPN (pour connexions clientes) ou "localhost" (pour RRAS)
- **Port** : Ports standards utilisés par le protocole
- **Méthode d'Auth** : Protocoles d'authentification configurés
- **Notes** : Avertissements de sécurité et recommandations

### Barre de statut
Affiche l'état actuel du scan et le nombre de configurations trouvées.


## Protocoles VPN supportés

### PPTP (Point-to-Point Tunneling Protocol)
- **Port** : TCP 1723
- **Sécurité** : OBSOLÈTE et VULNÉRABLE
- **Risques** :
  - Cryptage faible (MS-CHAPv2 cassable)
  - Vulnérabilités connues depuis 2012
  - Ne devrait plus être utilisé
- **Recommandation** : Migrer vers IKEv2 ou SSTP

### L2TP/IPSec (Layer 2 Tunneling Protocol over IPSec)
- **Ports** : UDP 1701 + IPSec (UDP 500, 4500)
- **Sécurité** : Correct si configuré avec certificats
- **Risques** :
  - PSK (Pre-Shared Key) faibles peuvent être bruteforcés
  - Bloqué par certains firewalls (NAT-T nécessaire)
- **Recommandation** : Utiliser des certificats plutôt que PSK

### SSTP (Secure Socket Tunneling Protocol)
- **Port** : TCP 443 (HTTPS)
- **Sécurité** : Bon (utilise SSL/TLS)
- **Avantages** :
  - Traverse facilement les firewalls (port 443)
  - Chiffrement fort via SSL/TLS
- **Limitation** : Propriétaire Microsoft (Windows uniquement)

### IKEv2 (Internet Key Exchange version 2)
- **Ports** : UDP 500, 4500
- **Sécurité** : EXCELLENT
- **Avantages** :
  - Standard moderne et sécurisé
  - Mobilité (reconnexion automatique)
  - Support des certificats
- **Recommandation** : Protocole recommandé pour nouveaux déploiements


## Méthodes d'authentification

### PAP (Password Authentication Protocol)
- **Sécurité** : CRITIQUE - Mots de passe en CLAIR
- **Risques** : Interception triviale des credentials
- **Recommandation** : NE JAMAIS UTILISER

### CHAP (Challenge Handshake Authentication Protocol)
- **Sécurité** : Faible - Hash MD5
- **Risques** : Vulnérable aux attaques par dictionnaire
- **Recommandation** : Éviter

### MS-CHAP (Microsoft CHAP)
- **Sécurité** : VULNÉRABLE
- **Risques** : Cassable avec outils publics (asleap, chapcrack)
- **Recommandation** : NE PAS UTILISER

### MS-CHAPv2 (Microsoft CHAP version 2)
- **Sécurité** : Faible (mais meilleur que v1)
- **Risques** : Vulnérable aux attaques sophistiquées
- **Recommandation** : Utiliser uniquement dans tunnel TLS/SSL (PEAP-MSCHAPv2)

### EAP (Extensible Authentication Protocol)
- **Sécurité** : BON à EXCELLENT (selon la méthode EAP)
- **Méthodes EAP** :
  - EAP-TLS : Certificats (le plus sécurisé)
  - PEAP-MSCHAPv2 : Tunnel TLS + MSCHAPv2
  - EAP-TTLS : Tunnel TLS
- **Recommandation** : EAP-TLS avec certificats


## 🔌 APIs Windows utilisées

### RAS API (Remote Access Service)
- **RasEnumEntriesW** : Énumère les connexions VPN configurées
- **RasGetEntryPropertiesW** : Récupère les propriétés d'une connexion (type, serveur, options)

### Registry API
- **RegOpenKeyExW** : Ouvre une clé de registre
- **RegQueryValueExW** : Lit une valeur de registre
- Clés interrogées :
  - `HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess` : Service RRAS
  - `HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters` : Configuration RRAS

### Service Control Manager
- **OpenSCManagerW** : Ouvre le gestionnaire de services
- **OpenServiceW** : Ouvre le service RemoteAccess
- **QueryServiceStatus** : Vérifie si RRAS est actif


## Environnement LAB-CONTROLLED

**AVERTISSEMENT CRITIQUE** : Cet outil est exclusivement destiné à un usage dans des environnements de laboratoire contrôlés.

### Utilisations légitimes
- Audit de sécurité autorisé sur vos propres configurations VPN
- Tests de conformité en environnement de développement
- Vérification des configurations avant déploiement en production
- Formation en cybersécurité
- Documentation des configurations existantes

### INTERDICTIONS STRICTES
- Auditer des configurations VPN sans autorisation
- Extraire ou exfiltrer les PSKs ou certificats
- Modifier les configurations VPN
- Utiliser pour intercepter le trafic VPN


## Logs

Les logs sont enregistrés dans :
```
%TEMP%\WinTools_VpnEndpointInspector_log.txt
```

Les logs contiennent :
- Horodatage de chaque opération
- Nombre de connexions trouvées
- Erreurs d'énumération RAS
- Opérations d'export


## Limitations

- N'extrait PAS les PSKs ou mots de passe (sécurité)
- Ne vérifie PAS la force des PSKs (stockés chiffrés par Windows)
- Ne teste PAS la connectivité aux serveurs VPN
- Ne vérifie PAS les certificats (expiration, validité)
- Nécessite des droits administrateur pour certaines infos RRAS
- Ne supporte que les connexions RAS Windows (pas OpenVPN, WireGuard, etc.)


## Interprétation des résultats

### Résultats critiques

**Type = "PPTP"** : VULNÉRABILITÉ CRITIQUE
- Protocole obsolète depuis 2012
- Cryptage MS-CHAPv2 cassable
- **ACTION IMMÉDIATE** : Migrer vers IKEv2 ou SSTP

**AuthMethod contient "PAP (FAIBLE)"** : VULNÉRABILITÉ CRITIQUE
- Mots de passe transmis en clair
- **ACTION IMMÉDIATE** : Désactiver PAP, utiliser EAP-TLS

**AuthMethod contient "MS-CHAP (FAIBLE)"** : RISQUE ÉLEVÉ
- Vulnérable aux attaques par dictionnaire
- **ACTION** : Migrer vers MS-CHAPv2 minimum, idéalement EAP

**Notes contient "Données non chiffrées"** : VULNÉRABILITÉ CRITIQUE
- Trafic VPN non chiffré (défaite du but du VPN!)
- **ACTION IMMÉDIATE** : Activer le chiffrement obligatoire

**Notes contient "Mot de passe non chiffré"** : RISQUE ÉLEVÉ
- Credentials vulnérables
- **ACTION** : Activer RequireEncryptedPw

### Résultats sains

**Type = "IKEv2"** : Excellent choix
- Protocole moderne et sécurisé
- Continue de vérifier l'authentification (EAP-TLS recommandé)

**Type = "SSTP"** : Bon choix
- Chiffrement SSL/TLS
- Traverse bien les firewalls

**AuthMethod = "EAP"** : Bonne configuration
- Vérifier que c'est EAP-TLS (certificats) et non PEAP-MSCHAPv2

**Notes = "Configuration semble correcte"** : Aucune vulnérabilité détectée
- Continue de vérifier régulièrement


## 🔒 Sécurité et Éthique

### Responsabilités de l'utilisateur

1. **Autorisation** : Auditer uniquement vos propres systèmes
2. **Confidentialité** : Ne pas divulguer les configurations découvertes
3. **Pas d'extraction** : Ne pas tenter d'extraire les PSKs ou certificats
4. **Légalité** : Respecter toutes les lois locales et internationales

### Bonnes pratiques de sécurisation VPN

1. **Protocoles** :
   - Utiliser IKEv2 ou SSTP (éviter PPTP)
   - Désactiver les protocoles obsolètes

2. **Authentification** :
   - Utiliser EAP-TLS avec certificats (le plus sécurisé)
   - Si PSK nécessaire : >20 caractères aléatoires
   - Éviter PAP, CHAP, MS-CHAP

3. **Chiffrement** :
   - Activer le chiffrement obligatoire (RequireDataEncryption)
   - Utiliser AES-256 minimum
   - Activer Perfect Forward Secrecy (PFS)

4. **Réseau** :
   - Split tunneling : désactiver si tout le trafic doit passer par VPN
   - Firewall : restreindre l'accès aux ports VPN
   - Logs : activer le logging des connexions

5. **Gestion** :
   - Renouveler régulièrement les certificats
   - Révoquer les certificats compromis
   - Auditer régulièrement les configurations
   - Désactiver les comptes VPN inutilisés

### Clause de non-responsabilité

L'auteur (Ayi NEDJIMI Consultants) et les contributeurs de cet outil déclinent toute responsabilité concernant :
- Les dommages directs ou indirects résultant de l'utilisation de cet outil
- Les utilisations illégales ou non éthiques
- Les pertes de données ou interruptions de service

**L'utilisateur assume l'entière responsabilité légale et éthique de l'utilisation de ce logiciel.**


## Support

Pour toute question ou problème :
- Consulter les logs dans %TEMP%\WinTools_VpnEndpointInspector_log.txt
- Vérifier que l'outil est lancé avec les droits administrateur
- S'assurer que des connexions VPN sont configurées


## 📄 Licence

Cet outil est fourni "TEL QUEL", sans garantie d'aucune sorte.

**Usage éducatif et professionnel uniquement dans des environnements autorisés.**

- --

**Ayi NEDJIMI Consultants - 2025**


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>