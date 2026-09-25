# Original scenario artifacts

The executable files in this directory are retained unchanged from baseline commit `43a7141c7753058e58bfb0894d4123236ce3d1b9`. This map supports static review and event attribution; it does not provide deployment instructions.

| File / region | Responsibility | Evidence relationship |
| --- | --- | --- |
| `setup.bat` | Launcher, temporary script-host artifact, privilege-related registry activity, temporary-artifact cleanup | Registry/process events and C1/S1/S2 |
| `payload.ps1`: outer script | Consumer-script materialization and named subscription management | File events and WMI 19/20/21 |
| `payload.ps1`: embedded script, discovery | Host/network/account information | Process/script telemetry and discovery output |
| Embedded script, collection/staging | Candidate file selection, history copies, manifest | File provenance and staging events |
| Embedded script, archive/transmission | ZIP creation, archive transmission, separate notifications | File/process/network attribution and receiver evidence |
| Embedded script, cleanup | Staging/archive deletion and history operation | File deletion evidence; not proof of complete eradication |

No refactor, execution change, or functional improvement is included in the documentation refresh. The absent optional `setup.hta` is documented as a repository completeness gap; no replacement is supplied.

See [scenario analysis](../docs/scenario-analysis.md) for technique scope and [case study](../docs/case-study.md) for what was actually observed.
