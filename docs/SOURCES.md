# Sources and legal notice

pan-ngfw-load contains and uses **no non-public data**. Everything a report shows about the firewall comes from the firewall itself - its tech support file or its read-only XML API. Datasheet values come only from the public product comparison of Palo Alto Networks, fetched on request ('pan-ngfw-load capacity update'); they are not part of pan-ngfw-load. Counter descriptions are those PAN-OS reports itself. The meaning of dataplane functions, resources and management-plane processes is inferred from their names and observed behaviour and is marked as such - it is not vendor documentation. The parsers were developed and tested with tech support files of firewalls the authors have access to; those files are not part of pan-ngfw-load and nothing from them is contained in it. pan-ngfw-load is an independent project, not affiliated with, endorsed by or supported by Palo Alto Networks. "Palo Alto Networks" and "PAN-OS" are trademarks of Palo Alto Networks, Inc.

| Used for | Source | Where |
|---|---|---|
| Model datasheet values (capacity, model limits) | Palo Alto Networks product comparison | https://www.paloaltonetworks.com/products/product-selection.html |
| Reference: end-of-sale / end-of-life dates of models | Palo Alto Networks end-of-life summary | https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary |
| CLI commands read from the firewall | PAN-OS CLI Quick Start | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start |
| XML API (live mode) | PAN-OS and Panorama API Usage Guide | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api |
| Tech support files, resource monitor, HA, interfaces | PAN-OS Administrator's Guide | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin |
| Background on counters and dataplane behaviour | Palo Alto Networks Knowledge Base | https://knowledgebase.paloaltonetworks.com |
| Counter descriptions | PAN-OS itself: 'show counter global' (description column) | in the tech support file / API output |
| Source code | pan-ngfw-load (MIT license) | https://github.com/dogbyter/pan-ngfw-load |

The same notice and list appear in the appendix of every report.
