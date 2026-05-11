import "hash"
import "math"
import "pe"

/*
================================================================================
 X3306 Elton MaaS Chain YARA Ruleset
 Author      : github.com/X-3306
 Date        : 2026-05-11
 Version     : 2.0.0
 Scope       : Defensive detection for Elton chain
 Report      : X-3306.MaaS.pdf
 Notes       : Indicators are intentionally stored in raw machine-usable form here.
================================================================================
*/

rule X3306_Elton_Chain_Known_Hashes
{
    meta:
        author = "github.com/X-3306"
        description = "Exact hash matches for known loader and Elton payload samples"
        date = "2026-05-11"
        version = "2.0.0"
        malware_family = "Elton"
        chain = "void.exe -> BK470009.exe -> Elton"
        confidence = "high"
        tlp = "WHITE"
    condition:
        hash.sha256(0, filesize) == "b58f0e8bed9fdde02c0abdafaa0eda5afa8a72c15aa6ac41d487ee2516d511bc" or
        hash.sha1(0, filesize) == "dba9fe66abcbce60dda25384afe06984e1c0db9c" or
        hash.md5(0, filesize) == "8e36104cb51ada0cb59ba7d4e1d7521f" or
        hash.sha256(0, filesize) == "2786cdf16d76e585a12cebb3b888a4e323915f2483cfa9a74bc20726272c1bc4" or
        hash.sha1(0, filesize) == "7297369403f860a6e3bca8e9397da54eb9159d6e" or
        hash.md5(0, filesize) == "823a85d7d8d697f96f33c71a40cbabe0"
}

rule X3306_Elton_Loader_PowerShell_Cradle
{
    meta:
        author = "github.com/X-3306"
        description = "Detects hidden PowerShell fetch-and-run cradles used by the initial loader and source-code infection"
        date = "2026-05-11"
        version = "2.0.0"
        stage = "loader"
        confidence = "high"
        tlp = "WHITE"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-WindowStyle Hidden" ascii wide nocase
        $ps3 = "-Command" ascii wide nocase
        $ps4 = "iwr -Uri" ascii wide nocase
        $ps5 = "Start-Process -FilePath" ascii wide nocase

        $drop1 = "BK470009.exe" ascii wide nocase
        $drop2 = "BK529815.exe" ascii wide nocase
        $path1 = "$env:APPDATA" ascii wide nocase
        $path2 = "$env:TEMP" ascii wide nocase

        $url1 = "exo-api.tf/Stb/Retev.php?bl=oy7DDikwUmXxyY968EPRE008.txt" ascii wide nocase
        $url2 = "vcc-library.uk/Stb/Retev.php?bl=oy7DDikwUmXxyY968EPRE008.txt" ascii wide nocase
        $camp = "oy7DDikwUmXxyY968EPRE008" ascii wide
    condition:
        filesize < 10MB and
        (
            (all of ($ps*) and 1 of ($drop*) and 1 of ($url*)) or
            (4 of ($ps*) and $camp and 1 of ($path*) and 1 of ($drop*)) or
            ($ps1 and $ps2 and $ps4 and $ps5 and 1 of ($drop*) and 1 of ($path*))
        )
}

rule X3306_Elton_BK470009_Stager
{
    meta:
        author = "github.com/X-3306"
        description = "Detects BK470009.exe stager by unique stack string, staging paths, and anti-analysis markers"
        date = "2026-05-11"
        version = "2.0.0"
        stage = "stager"
        confidence = "high"
        tlp = "WHITE"
    strings:
        $unique_stack = "fo8yndd9ybn81i0u9x1hxuuxnlvgvf" ascii wide
        $campaign = "oy7DDikwUmXxyY968EPRE008" ascii wide

        $api_hash_hint1 = "InternetOpenA" ascii wide
        $api_hash_hint2 = "InternetConnectA" ascii wide

        $anti1 = "wine_get_version" ascii wide
        $anti2 = "NtQuerySystemInformation" ascii wide
        $anti3 = "GetProcAddress" ascii wide
        $anti4 = "dllhost.exe" ascii wide nocase

        $infra1 = "raw.githubusercontent.com" ascii wide nocase
        $infra2 = "XxXloverXx" ascii wide nocase
        $infra3 = "rustflare" ascii wide nocase
        $infra4 = "/refs/heads/main/engine" ascii wide nocase
        $infra5 = "/refs/heads/main/crates/engine" ascii wide nocase
        $infra6 = "exo-api.tf" ascii wide nocase
        $infra7 = "vcc-library.uk" ascii wide nocase
        $infra8 = "dhszo.darkside.cy" ascii wide nocase
        $infra9 = "api.darkside.cy" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and
        filesize < 25MB and
        (
            $unique_stack or
            ($campaign and 2 of ($infra*)) or
            (all of ($api_hash_hint*) and 1 of ($infra*)) or
            (2 of ($anti*) and 2 of ($infra*)) or
            (pe.machine == pe.MACHINE_AMD64 and math.entropy(0, filesize) > 5.8 and 3 of ($infra*) and 1 of ($anti*))
        )
}

rule X3306_Elton_Final_Payload_Behavioral
{
    meta:
        author = "github.com/X-3306"
        description = "Detects Elton final payload behavior: anti-analysis, credential theft, crypto, and RAT/infostealer capability markers"
        date = "2026-05-11"
        version = "2.0.0"
        stage = "final-payload"
        confidence = "medium-high"
        tlp = "WHITE"
    strings:
        $anti1 = "wine_get_version" ascii wide
        $anti2 = "NtQuerySystemInformation" ascii wide
        $anti3 = "No Internet to download!" ascii wide
        $anti4 = "darkside always runs." ascii wide nocase
        $anti5 = "No Compatible GPU" ascii wide nocase

        $cred1 = "CryptUnprotectData" ascii wide
        $cred2 = "Login Data" ascii wide
        $cred3 = "Local State" ascii wide
        $cred4 = "with_sqlite" ascii wide nocase
        $cred5 = "Telegram Found, Harvesting" ascii wide
        $cred6 = "connection_hash" ascii wide

        $crypto1 = "RijnDael_AES_CHAR" ascii wide
        $crypto2 = "Chacha_256" ascii wide
        $crypto3 = "BASE64" ascii wide
        $crypto4 = "FKSHTBF" ascii wide

        $network1 = "Mozilla/5.0 (Windows NT 14_73_31; WOW64)" ascii wide
        $network2 = "bot.whatismyipaddress.com" ascii wide nocase
        $network3 = "bobby31.php" ascii wide nocase
        $network4 = "Daytone" ascii wide
        $network5 = "id=Elton" ascii wide nocase

        $uac1 = "ComputerDefaults.exe" ascii wide nocase
        $uac2 = "ms-settings\\Shell\\Open\\command" ascii wide nocase
        $uac3 = "DelegateExecute" ascii wide nocase

        $prank1 = "screen_melt" ascii wide
        $prank2 = "matrix_rain" ascii wide
        $prank3 = "glitch_bands" ascii wide
        $prank4 = "invert_colors" ascii wide
        $prank5 = "cursor_trails" ascii wide
        $prank6 = "jumpscare_classic" ascii wide
        $prank7 = "jumpscare_screamer" ascii wide
        $prank8 = "CRITICAL_PROCESS_DIED" ascii wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 30MB and
        (
            (2 of ($cred*) and 2 of ($crypto*) and 1 of ($network*)) or
            (2 of ($anti*) and 2 of ($cred*) and 1 of ($network*)) or
            (2 of ($uac*) and 2 of ($cred*)) or
            (4 of ($prank*) and 1 of ($network*)) or
            ($network1 and 2 of ($cred*)) or
            ($network3 and $network4 and 2 of ($cred*))
        )
}

rule X3306_Elton_Source_Code_Infection
{
    meta:
        author = "github.com/X-3306"
        description = "Detects Visual Studio / ImGui source-code infection strings and build-event loader insertion"
        date = "2026-05-11"
        version = "2.0.0"
        stage = "supply-chain"
        confidence = "high"
        tlp = "WHITE"
    strings:
        $proj1 = "[VCXPROJ] Found %i .vcxproj Files" ascii wide
        $proj2 = "[CSPROJ] Found %i .csproj Files" ascii wide
        $proj3 = "[IMGUI CPP] Found %i imgui_impl_win32.cpp Files" ascii wide
        $proj4 = ".vcxproj" ascii wide nocase
        $proj5 = ".csproj" ascii wide nocase
        $proj6 = "imgui_impl_win32.cpp" ascii wide nocase
        $proj7 = "PreBuildEvent" ascii wide nocase

        $loader1 = "powershell" ascii wide nocase
        $loader2 = "-WindowStyle Hidden" ascii wide nocase
        $loader3 = "iwr -Uri" ascii wide nocase
        $loader4 = "Start-Process -FilePath" ascii wide nocase
        $loader5 = "BK470009.exe" ascii wide nocase
        $loader6 = "BK529815.exe" ascii wide nocase
    condition:
        filesize < 30MB and
        (
            all of ($proj1, $proj2, $proj3) or
            ($proj6 and $proj7 and 3 of ($loader*)) or
            (3 of ($proj*) and 3 of ($loader*)) or
            ($proj1 and $proj2 and 2 of ($loader*))
        )
}

rule X3306_Elton_C2_Intake_Endpoint
{
    meta:
        author = "github.com/X-3306"
        description = "Detects C2 ZIP intake artifacts around bobby31.php, Daytone, and APLA endpoint types"
        date = "2026-05-11"
        version = "2.0.0"
        stage = "c2-intake"
        confidence = "medium-high"
        tlp = "WHITE"
    strings:
        $endpoint = "bobby31.php" ascii wide nocase
        $sec = "security=Daytone" ascii wide
        $type1 = "type=APLADEX" ascii wide
        $type2 = "type=APLATG" ascii wide
        $type3 = "type=pssprc" ascii wide
        $resp1 = "X1" ascii wide
        $resp2 = "X3" ascii wide
        $php1 = "Error code: Array" ascii wide
        $form1 = "multipart/form-data" ascii wide nocase
        $form2 = "Content-Disposition: form-data" ascii wide nocase
        $zip1 = { 50 4B 03 04 }
        $domain = "balista.lol" ascii wide nocase
    condition:
        (
            $endpoint and $sec and 1 of ($type*) and 1 of ($form*)
        ) or (
            $domain and $endpoint and 2 of ($type*)
        ) or (
            $endpoint and $php1 and 1 of ($type*)
        ) or (
            $endpoint and $sec and 1 of ($resp*)
        ) or (
            $endpoint and $sec and $zip1 at 0
        )
}

rule X3306_Darkside_MaaS_Panel_HTML
{
    meta:
        author = "github.com/X-3306"
        description = "Detects Darkside-branded MaaS panel HTML/source telemetry artifacts"
        date = "2026-05-11"
        version = "2.0.0"
        artifact = "panel-html"
        confidence = "high"
        tlp = "WHITE"
    strings:
        $op1 = "Yes bitches i log all login data" ascii nocase
        $op2 = "better not use 1 acc with multiple people" ascii nocase
        $op3 = "ill suspend the acc" ascii nocase

        $tele1 = "screen_width" ascii
        $tele2 = "screen_height" ascii
        $tele3 = "timezone" ascii
        $tele4 = "local_time" ascii
        $tele5 = "cpu_cores" ascii
        $tele6 = "device_ram" ascii
        $tele7 = "gpu_renderer" ascii
        $tele8 = "browser_name" ascii
        $tele9 = "network_latency" ascii
        $tele10 = "accepted_languages" ascii
        $webgl1 = "WEBGL_debug_renderer_info" ascii
        $webgl2 = "UNMASKED_RENDERER_WEBGL" ascii
        $webgl3 = "getGPUInfo" ascii

        $dom1 = "dhszo.darkside.cy" ascii nocase
        $dom2 = "darkside.cy" ascii nocase
    condition:
        $op1 or
        ($op2 and $op3) or
        (1 of ($dom*) and 6 of ($tele*) and 2 of ($webgl*)) or
        (8 of ($tele*) and 2 of ($webgl*))
}

rule X3306_Elton_Infrastructure_Strings
{
    meta:
        author = "github.com/X-3306"
        description = "Detects raw infrastructure, routing, fake UA, and campaign identifiers tied to the Elton MaaS chain"
        date = "2026-05-11"
        version = "2.0.0"
        artifact = "network-or-config"
        confidence = "medium"
        tlp = "WHITE"
    strings:
        $domain1 = "exo-api.tf" ascii wide nocase
        $domain2 = "dhszo.darkside.cy" ascii wide nocase
        $domain3 = "api.darkside.cy" ascii wide nocase
        $domain4 = "balista.lol" ascii wide nocase
        $domain5 = "rshosting.xyz" ascii wide nocase
        $domain6 = "vcc-library.uk" ascii wide nocase
        $domain7 = "pee-files.nl" ascii wide nocase
        $domain8 = "test.recklessroleplay.com" ascii wide nocase
        $domain9 = "raw.githubusercontent.com" ascii wide nocase

        $path1 = "/Stb/Retev.php?bl=" ascii wide
        $path2 = "/PokerFace/init.php?id=Elton" ascii wide
        $path3 = "/Stb/PokerFace/" ascii wide
        $path4 = "/rustflare/" ascii wide
        $path5 = "refs/heads/main/crates/engine" ascii wide
        $path6 = "dashboard.html" ascii wide nocase

        $id1 = "oy7DDikwUmXxyY968EPRE008" ascii wide
        $id2 = "1399862658039156736" ascii wide
        $ua1 = "Mozilla/5.0 (Windows NT 14_73_31; WOW64)" ascii wide
        $mutex = "Global\\PFNX_SideQE" ascii wide
    condition:
        $ua1 or
        ($id1 and 1 of ($domain*) and 1 of ($path*)) or
        ($id2 and 1 of ($domain*)) or
        (2 of ($domain*) and 2 of ($path*)) or
        ($domain9 and $path4) or
        ($mutex and 1 of ($domain*))
}

rule X3306_Elton_C2PA_Logo_Metadata
{
    meta:
        author = "github.com/X-3306"
        description = "Detects campaign logo provenance metadata, not malware code"
        date = "2026-05-11"
        version = "2.0.0"
        artifact = "logo-c2pa"
        confidence = "medium"
        tlp = "WHITE"
    strings:
        $urn = "urn:c2pa:94852476-5481-40ea-ae92-b0f62cae5ac2" ascii
        $iid = "xmp:iid:1627d07b-ca57-42d9-b909-f981a223dd6b" ascii
        $gen1 = "ChatGPT" ascii
        $gen2 = "GPT-4o" ascii
        $src = "trainedAlgorithmicMedia" ascii
        $assert1 = "c2pa.actions.v2" ascii
        $assert2 = "c2pa.hash.data" ascii
        $assert3 = "c2pa.thumbnail.ingredient" ascii
    condition:
        ($urn and $iid) or
        ($src and 2 of ($assert*) and 1 of ($gen*))
}
