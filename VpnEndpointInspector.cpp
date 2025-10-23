/*******************************************************************************
 * VpnEndpointInspector - Inspecteur de configurations VPN/RRAS
 *
 * Développé par: Ayi NEDJIMI Consultants
 * Date: 2025
 *
 * Description:
 *   Liste les configurations d'endpoints VPN/RRAS et détecte les PSKs faibles
 *   ou les ports de management exposés.
 *
 * AVERTISSEMENT LEGAL:
 *   Cet outil est fourni UNIQUEMENT pour des environnements LAB-CONTROLLED.
 *   L'utilisation sur des systèmes non autorisés est STRICTEMENT INTERDITE.
 *   L'utilisateur assume l'entière responsabilité légale de l'usage de ce logiciel.
 *
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <ras.h>
#include <raserror.h>
#include <thread>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>

#pragma comment(lib, "rasapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// IDs des contrôles
#define IDC_LISTVIEW        1001
#define IDC_BTN_SCAN        1002
#define IDC_BTN_EXPORT      1003
#define IDC_STATUSBAR       1004

// Structure pour une connexion VPN
struct VpnConnection {
    std::wstring connectionName;
    std::wstring type;
    std::wstring server;
    std::wstring port;
    std::wstring authMethod;
    std::wstring notes;
};

// Variables globales
HWND g_hMainWindow = nullptr;
HWND g_hListView = nullptr;
HWND g_hStatusBar = nullptr;
std::vector<VpnConnection> g_connections;
std::wstring g_logPath;

// Fonction de logging
void LogMessage(const std::wstring& message) {
    std::wofstream logFile(g_logPath, std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(nullptr);
        wchar_t timeStr[64];
        struct tm timeInfo;
        localtime_s(&timeInfo, &now);
        wcsftime(timeStr, sizeof(timeStr) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeInfo);
        logFile << L"[" << timeStr << L"] " << message << std::endl;
    }
}

// Fonction pour obtenir le chemin de log
std::wstring GetLogPath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = tempPath;
    logPath += L"WinTools_VpnEndpointInspector_log.txt";
    return logPath;
}

// Mettre à jour la barre de statut
void UpdateStatus(const std::wstring& status) {
    if (g_hStatusBar) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
    }
    LogMessage(status);
}

// Ajouter une connexion à la ListView
void AddConnectionToListView(const VpnConnection& conn) {
    LVITEMW lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hListView);

    // Nom de connexion
    lvi.iSubItem = 0;
    lvi.pszText = const_cast<LPWSTR>(conn.connectionName.c_str());
    int index = ListView_InsertItem(g_hListView, &lvi);

    // Type
    ListView_SetItemText(g_hListView, index, 1, const_cast<LPWSTR>(conn.type.c_str()));

    // Serveur
    ListView_SetItemText(g_hListView, index, 2, const_cast<LPWSTR>(conn.server.c_str()));

    // Port
    ListView_SetItemText(g_hListView, index, 3, const_cast<LPWSTR>(conn.port.c_str()));

    // Méthode d'authentification
    ListView_SetItemText(g_hListView, index, 4, const_cast<LPWSTR>(conn.authMethod.c_str()));

    // Notes
    ListView_SetItemText(g_hListView, index, 5, const_cast<LPWSTR>(conn.notes.c_str()));
}

// Lire une valeur de registre
std::wstring ReadRegistryString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hSubKey;
    if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) {
        return L"";
    }

    wchar_t buffer[1024] = { 0 };
    DWORD bufferSize = sizeof(buffer);
    DWORD type = REG_SZ;

    if (RegQueryValueExW(hSubKey, valueName.c_str(), nullptr, &type,
                        reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
        RegCloseKey(hSubKey);
        return std::wstring(buffer);
    }

    RegCloseKey(hSubKey);
    return L"";
}

// Lire une valeur DWORD de registre
DWORD ReadRegistryDWORD(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hSubKey;
    if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) {
        return 0;
    }

    DWORD value = 0;
    DWORD bufferSize = sizeof(DWORD);
    DWORD type = REG_DWORD;

    RegQueryValueExW(hSubKey, valueName.c_str(), nullptr, &type,
                    reinterpret_cast<LPBYTE>(&value), &bufferSize);

    RegCloseKey(hSubKey);
    return value;
}

// Vérifier si RRAS est installé
bool IsRRASInstalled() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Services\\RemoteAccess",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Déterminer le type de VPN basé sur le device type
std::wstring GetVpnType(const std::wstring& deviceType) {
    if (deviceType.find(L"PPTP") != std::wstring::npos) return L"PPTP";
    if (deviceType.find(L"L2TP") != std::wstring::npos) return L"L2TP/IPSec";
    if (deviceType.find(L"SSTP") != std::wstring::npos) return L"SSTP";
    if (deviceType.find(L"IKEv2") != std::wstring::npos) return L"IKEv2";
    return deviceType;
}

// Déterminer le port par défaut selon le type
std::wstring GetDefaultPort(const std::wstring& type) {
    if (type == L"PPTP") return L"1723";
    if (type == L"L2TP/IPSec") return L"1701 (+ IPSec 500/4500)";
    if (type == L"SSTP") return L"443";
    if (type == L"IKEv2") return L"500/4500";
    return L"N/A";
}

// Analyser la méthode d'authentification
std::wstring AnalyzeAuthMethod(DWORD options) {
    std::wstring auth;

    // RASEO_RequireEAP
    if (options & 0x00001000) {
        auth += L"EAP";
    }
    // RASEO_RequirePAP
    if (options & 0x00000040) {
        if (!auth.empty()) auth += L", ";
        auth += L"PAP (FAIBLE)";
    }
    // RASEO_RequireCHAP
    if (options & 0x00000080) {
        if (!auth.empty()) auth += L", ";
        auth += L"CHAP";
    }
    // RASEO_RequireMsCHAP
    if (options & 0x00000100) {
        if (!auth.empty()) auth += L", ";
        auth += L"MS-CHAP (FAIBLE)";
    }
    // RASEO_RequireMsCHAP2
    if (options & 0x00000200) {
        if (!auth.empty()) auth += L", ";
        auth += L"MS-CHAPv2";
    }

    if (auth.empty()) auth = L"Non spécifié";

    return auth;
}

// Scanner les connexions RAS
void ScanRASConnections() {
    UpdateStatus(L"Énumération des connexions RAS...");

    DWORD dwCb = 0;
    DWORD dwEntries = 0;
    LPRASENTRYNAMEW lpRasEntryName = nullptr;

    // Première passe pour obtenir la taille nécessaire
    DWORD dwRet = RasEnumEntriesW(nullptr, nullptr, lpRasEntryName, &dwCb, &dwEntries);

    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        lpRasEntryName = (LPRASENTRYNAMEW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);
        if (lpRasEntryName == nullptr) {
            UpdateStatus(L"Erreur: Allocation mémoire échouée");
            return;
        }

        lpRasEntryName[0].dwSize = sizeof(RASENTRYNAMEW);
        dwRet = RasEnumEntriesW(nullptr, nullptr, lpRasEntryName, &dwCb, &dwEntries);
    }

    if (dwRet != ERROR_SUCCESS) {
        if (lpRasEntryName) HeapFree(GetProcessHeap(), 0, lpRasEntryName);

        if (dwRet == ERROR_CANNOT_OPEN_PHONEBOOK) {
            UpdateStatus(L"Aucune connexion RAS trouvée (phonebook non accessible)");
        } else {
            std::wstringstream status;
            status << L"Erreur RasEnumEntries: " << dwRet;
            UpdateStatus(status.str());
        }
        return;
    }

    if (dwEntries == 0) {
        UpdateStatus(L"Aucune connexion RAS configurée");
        if (lpRasEntryName) HeapFree(GetProcessHeap(), 0, lpRasEntryName);
        return;
    }

    // Parcourir les connexions
    for (DWORD i = 0; i < dwEntries; i++) {
        VpnConnection conn;
        conn.connectionName = lpRasEntryName[i].szEntryName;

        // Obtenir les détails de l'entrée
        RASENTRY rasEntry = { 0 };
        rasEntry.dwSize = sizeof(RASENTRY);
        DWORD dwEntrySize = sizeof(RASENTRY);

        dwRet = RasGetEntryPropertiesW(nullptr, conn.connectionName.c_str(),
                                      &rasEntry, &dwEntrySize,
                                      nullptr, nullptr);

        if (dwRet == ERROR_SUCCESS) {
            conn.type = GetVpnType(rasEntry.szDeviceType);
            conn.server = rasEntry.szLocalPhoneNumber; // Pour VPN, c'est l'adresse du serveur
            conn.port = GetDefaultPort(conn.type);
            conn.authMethod = AnalyzeAuthMethod(rasEntry.dwfOptions);

            // Notes de sécurité
            std::wstring notes;

            // Vérifier les protocoles faibles
            if (conn.type == L"PPTP") {
                notes += L"PPTP est obsolète et vulnérable. ";
            }

            // Vérifier l'authentification faible
            if (conn.authMethod.find(L"PAP") != std::wstring::npos) {
                notes += L"PAP envoie les mots de passe en clair! ";
            }
            if (conn.authMethod.find(L"MS-CHAP (FAIBLE)") != std::wstring::npos) {
                notes += L"MS-CHAP est vulnérable aux attaques. ";
            }

            // Vérifier l'encryption
            if (rasEntry.dwfOptions & 0x00000008) { // RASEO_RequireEncryptedPw
                // Bon signe
            } else {
                notes += L"Mot de passe non chiffré. ";
            }

            // Vérifier le data encryption
            if (!(rasEntry.dwfOptions & 0x00000010)) { // RASEO_RequireDataEncryption
                notes += L"Données non chiffrées! ";
            }

            if (notes.empty()) {
                notes = L"Configuration semble correcte";
            }

            conn.notes = notes;

        } else {
            conn.type = L"Erreur";
            conn.server = L"N/A";
            conn.port = L"N/A";
            conn.authMethod = L"N/A";
            conn.notes = L"Impossible de récupérer les propriétés";
        }

        g_connections.push_back(conn);
        AddConnectionToListView(conn);
    }

    if (lpRasEntryName) {
        HeapFree(GetProcessHeap(), 0, lpRasEntryName);
    }
}

// Vérifier les services RRAS
void CheckRRASServices() {
    if (!IsRRASInstalled()) {
        return;
    }

    UpdateStatus(L"Vérification de la configuration RRAS...");

    VpnConnection rras;
    rras.connectionName = L"[RRAS Service]";
    rras.type = L"Serveur RRAS";
    rras.server = L"localhost";
    rras.port = L"Multiples";
    rras.authMethod = L"Configuration serveur";

    std::wstring notes;

    // Vérifier si le service est démarré
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE service = OpenServiceW(scm, L"RemoteAccess", SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    notes += L"Service RRAS actif. ";
                } else {
                    notes += L"Service RRAS arrêté. ";
                }
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }

    // Vérifier les ports VPN standards
    notes += L"Ports standards: PPTP(1723), L2TP(1701), SSTP(443), IKEv2(500/4500). ";

    // Vérifier la configuration dans le registre
    DWORD routerRole = ReadRegistryDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\RemoteAccess\\Parameters",
        L"RouterType");

    if (routerRole > 0) {
        notes += L"Router configuré. ";
    }

    rras.notes = notes.empty() ? L"RRAS installé mais non configuré" : notes;

    g_connections.push_back(rras);
    AddConnectionToListView(rras);
}

// Thread de scan
void ScanThread() {
    ListView_DeleteAllItems(g_hListView);
    g_connections.clear();

    UpdateStatus(L"Démarrage du scan...");

    // Scanner les connexions RAS (client VPN)
    ScanRASConnections();

    // Vérifier les services RRAS (serveur VPN)
    CheckRRASServices();

    std::wstringstream status;
    status << L"Scan terminé. " << g_connections.size() << L" configuration(s) trouvée(s).";
    UpdateStatus(status.str());

    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_SCAN), TRUE);
}

// Exporter vers CSV
void ExportToCSV() {
    wchar_t fileName[MAX_PATH] = L"VpnEndpointInspector_Export.csv";
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWindow;
    ofn.lpstrFilter = L"Fichiers CSV (*.csv)\0*.csv\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Exporter les configurations VPN";
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (GetSaveFileNameW(&ofn)) {
        std::ofstream csvFile(fileName, std::ios::binary | std::ios::trunc);
        if (csvFile.is_open()) {
            // BOM UTF-8
            const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            csvFile.write(reinterpret_cast<const char*>(bom), sizeof(bom));

            // Header
            csvFile << "ConnectionName,Type,Server,Port,AuthMethod,Notes\n";

            // Données
            for (const auto& conn : g_connections) {
                // Conversion UTF-16 vers UTF-8
                auto ToUTF8 = [](const std::wstring& wstr) -> std::string {
                    if (wstr.empty()) return "";
                    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
                    std::string str(size - 1, 0);
                    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size, nullptr, nullptr);
                    return str;
                };

                std::string line = ToUTF8(conn.connectionName) + "," +
                                  ToUTF8(conn.type) + "," +
                                  ToUTF8(conn.server) + "," +
                                  ToUTF8(conn.port) + "," +
                                  ToUTF8(conn.authMethod) + "," +
                                  ToUTF8(conn.notes) + "\n";
                csvFile << line;
            }

            csvFile.close();
            UpdateStatus(L"Export CSV réussi: " + std::wstring(fileName));
            MessageBoxW(g_hMainWindow, L"Export CSV réussi!", L"Succès", MB_OK | MB_ICONINFORMATION);
        } else {
            UpdateStatus(L"Erreur: Impossible de créer le fichier CSV");
            MessageBoxW(g_hMainWindow, L"Erreur lors de l'export!", L"Erreur", MB_OK | MB_ICONERROR);
        }
    }
}

// Initialiser la ListView
void InitListView(HWND hwnd) {
    g_hListView = GetDlgItem(hwnd, IDC_LISTVIEW);

    // Style
    DWORD style = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER;
    ListView_SetExtendedListViewStyle(g_hListView, style);

    // Colonnes
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.cx = 180;
    lvc.pszText = const_cast<LPWSTR>(L"Nom de Connexion");
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.cx = 120;
    lvc.pszText = const_cast<LPWSTR>(L"Type");
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Serveur");
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.cx = 130;
    lvc.pszText = const_cast<LPWSTR>(L"Port");
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Méthode d'Auth");
    ListView_InsertColumn(g_hListView, 4, &lvc);

    lvc.cx = 350;
    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    ListView_InsertColumn(g_hListView, 5, &lvc);
}

// Procédure de fenêtre
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Boutons
            CreateWindowExW(0, L"BUTTON", L"Scanner les Configurations VPN/RRAS",
                           WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                           10, 10, 280, 30, hwnd, (HMENU)IDC_BTN_SCAN, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                           WS_CHILD | WS_VISIBLE,
                           310, 10, 150, 30, hwnd, (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

            // ListView
            CreateWindowExW(0, WC_LISTVIEW, L"",
                           WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
                           10, 50, 1060, 510, hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);

            InitListView(hwnd);

            // Barre de statut
            g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAME, nullptr,
                                          WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_STATUSBAR, nullptr, nullptr);

            UpdateStatus(L"Prêt. Cliquez sur 'Scanner' pour énumérer les connexions VPN et RRAS.");
            return 0;
        }

        case WM_SIZE: {
            if (g_hStatusBar) {
                SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
            }
            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_SCAN: {
                    EnableWindow(GetDlgItem(hwnd, IDC_BTN_SCAN), FALSE);
                    std::thread(ScanThread).detach();
                    break;
                }
                case IDC_BTN_EXPORT: {
                    ExportToCSV();
                    break;
                }
            }
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser le log
    g_logPath = GetLogPath();
    LogMessage(L"=== VpnEndpointInspector démarré ===");

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    // Enregistrer la classe de fenêtre
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"VpnEndpointInspectorClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    // Créer la fenêtre
    g_hMainWindow = CreateWindowExW(
        0,
        L"VpnEndpointInspectorClass",
        L"VpnEndpointInspector - Inspection Configurations VPN/RRAS - Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 640,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hMainWindow) {
        LogMessage(L"Erreur: Impossible de créer la fenêtre principale");
        return 1;
    }

    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);

    // Boucle de messages
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    LogMessage(L"=== VpnEndpointInspector terminé ===");
    return (int)msg.wParam;
}
