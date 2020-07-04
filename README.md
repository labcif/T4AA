# LabCIF - TikTok for Android Analyzer 
#### Module for Autopsy Forensic Browser
## Getting Started

TikTok application extension for Android Analyzer running on Autopsy

## Artifacts
* TikTok messages
* TikTok contacts

## Prerequisites

* [Autopsy](https://www.sleuthkit.org/autopsy/)


### Running from Autopsy

Since the Android Analyzer is an internal module of Autopsy, it will not appear in the directory of external modules python_modules. The internal modules can be found in the sub-directory:
*autopsy/InternalPythonModules* where the contents of Autopsy are present. By default, in the Windows 10 operating system, the directory is:
*C:/ProgramFiles/Autopsy-4.15.0/autopsy/InternalPythonModules*.


1. Move the *tiktok.py* file to the Internal Python Modules folder.
2. Add TikTok dependency on *module.py* file.

```python 
import tiktok
```

To add the TikTok dependency in the module.py file, add the line “*import tiktok*” in the imports section.

3. Add TikTok analyzer to the list of analysers already in *module.py*.

```python
analyzers = [contact.ContactAnalyzer(),
calllog.CallLogAnalyzer(),
textmessage.TextMessageAnalyzer(),
tangomessage.TangoMessageAnalyzer(),
wwfmessage.WWFMessageAnalyzer(),
googlemaplocation.GoogleMapLocationAnalyzer(),
browserlocation.BrowserLocationAnalyzer(),
cachelocation.CacheLocationAnalyzer(),
imo.IMOAnalyzer(),xender.XenderAnalyzer(), zapya.ZapyaAnalyzer(), shareit.ShareItAnalyzer(), line.LineAnalyzer(), whatsapp.WhatsAppAnalyzer(), textnow.TextNowAnalyzer(), skype.SkypeAnalyzer(),
viber.ViberAnalyzer(),
fbmessenger.FBMessengerAnalyzer(), sbrowser.SBrowserAnalyzer(), operabrowser.OperaAnalyzer(), oruxmaps.OruxMapsAnalyzer(), tiktok.TiktokAnalyzer(),
installedapps.InstalledApplicationsAnalyzer()]
```
       


## Authors

* **Patrício Domingues** - [GitHub](https://github.com/PatricioDomingues)
* **Ruben Nogueira** - [GitHub](https://github.com/rubnogueira)
* **José Francisco** - [GitHub](https://github.com/98jfran)
* **Miguel Frade** - [GitHub](https://github.com/mfrade)

Project developed as final project for Computer Engineering course in Escola Superior de Tecnologia e Gestão de Leiria.

## Environments Tested

* Autopsy 4.14
* Autopsy 4.15

## License

GNU General Public License v3.0

## Notes

* Made with ❤ in Leiria, Portugal
