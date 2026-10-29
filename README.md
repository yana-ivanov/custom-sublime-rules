# Custom Sublime Rules

Email detection rules written in [MQL](https://sublime.security/blog/introduction-to-message-query-language-mql/) for the [Sublime Security](https://sublime.security) platform, by [Yana Ivanov](https://yanaivanov.com) ([@ArtemisHex_](https://x.com/ArtemisHex_)).

Twenty-five rules, each written from a specific technique or campaign rather than from a list of indicators. Broadly applicable rules go upstream to the main Sublime rules repository; this feed keeps the narrower lures, the specific brand impersonations, and the detections still collecting evidence. All of them are free to take, adapt or submit upstream.

## Subscribing

Add this repository as a custom rule feed in your Sublime instance. The [rule feeds documentation](https://docs.sublime.security/docs/rule-feeds) covers the steps. Rules live in `detection-rules/`, one YAML file each.

```
https://github.com/yana-ivanov/custom-sublime-rules
```

## These rules have been tested

Every rule here has been run against a real mailbox: 4,033 inbound messages across thirty days, one hunt per rule. That is unusual enough to be worth stating, and the results are published in full rather than summarised favourably.

| Result | |
|---|---|
| Rules that fired at all | 2 of 25 |
| Total matches | 27 |
| True positives | 0 |
| False positives | 27 |

The test corpus was a personal mailbox, which contains no wire fraud, no tax authority impersonation and no RMM abuse, and which Google had already filtered before the platform saw it. Twenty-three rules firing zero times is a statement about that corpus, not evidence the rules work. The two that did fire are documented below.

The whole exercise, including what it says about writing rules you cannot test, is written up here: **[Twenty-Five Rules I Had Never Run](https://yanaivanov.com/writing/rule_feed_field_note.html)**.

## Covering gaps, no equivalent found upstream

Narrow by design, but with no close match in the public [sublime-rules](https://github.com/sublime-security/sublime-rules) ruleset as of October 2026. If you are looking for something here worth taking, start with these.

| Rule | Catches | Requires |
|---|---|---|
| `attachment_pkpass_apple_wallet_pass_from_unsolicited_sender_with_suspic` | Apple Wallet passes used as a delivery format from unsolicited senders | Link Analysis |
| `brand_impersonation_gotoresolve_goto_rmm_remote_support_lure` | GoToResolve remote support lures. The ruleset covers ScreenConnect but not GoTo | |
| `brand_impersonation_n_able_n_central_rmm_patch_or_update_lure` | N-able N-central patch and update lures, the same RMM gap | |
| `link_microsoft_365_entra_doppelganger_domain` | Entra look-alike domains used for adversary-in-the-middle credential phishing | |
| `link_claims_tld_domain_with_it_support_or_help_desk_impersonation` | `.claims` domains posing as IT support, used as a vishing precursor | |
| `attachment_pdf_with_job_offer_lure_and_dangerous_action_keys` | Job offer PDFs carrying dangerous action keys, the Operation Dream Job pattern | |
| `attachment_unicode_homoglyph_characters_in_filename` | Look-alike Unicode characters hidden in attachment filenames | |
| `body_css_injection_patterns_consistent_with_webmail_sanitizer_byp` | CSS injection used to defeat webmail sanitisers and harvest credentials | |
| `link_framer_hosted_page_with_credential_phishing_indicators` | Credential phishing hosted on Framer, a legitimate site builder | Link Analysis |
| `link_hugging_face_model_or_repository_link_from_first_contact_sen` | Hugging Face model and repository links from first-contact senders | |

The RMM pair is the clearest gap. The public ruleset carries three ScreenConnect rules, so remote monitoring abuse is already an accepted category, and GoToResolve and N-able are the obvious holes in it.

## Related coverage already exists

These overlap with existing public rules to some degree. Listed with what to compare against, so nobody wastes time rediscovering it.

| Rule | Catches | Nearest existing coverage |
|---|---|---|
| `link_developer_recruitment_lure_with_fake_technical_assessment_or` | Fake technical assessments sent to developers, the Contagious Interview pattern | `link_job_recruitment_lure_with_suspicious_hosting` |
| `link_microsoft_device_code_lure_in_email_body` | Microsoft device code phishing delivered in the message body | two device code rules |
| `link_screenconnect_cloud_hosted_c2_subdomain_from_unsolicited_sen` | ScreenConnect subdomains used as command and control | three ScreenConnect rules |
| `link_figma_file_invite_or_project_link_from_first_contact_sender` | Figma invites from senders with no prior contact | two Figma rules |
| `link_azure_blob_storage_hosted_credential_phishing_page_from_unso` | Credential phishing pages hosted on Azure Blob Storage | two blob storage rules |
| `attachment_india_tax_authority_impersonation_with_malicious_archive_or_` | ITR and GST filing season lures impersonating Indian tax authorities | one tax authority rule |
| `attachment_zip_containing_lnk_file_with_github_raw_content_link` | LNK files inside archives pulling from GitHub raw content | two LNK delivery rules |
| `bec_real_estate_closing_wire_fraud` | Title company and closing attorney impersonation around wire instructions | several BEC and wire fraud rules |
| `service_abuse_jira_service_management_invite_with_phishing_or_callback_lur` | Jira Service Management invites carrying phishing or callback lures | several Atlassian rules |
| `attachment_script_file_delivered_directly_double_extension_or_unsolicit` | Script files delivered directly or behind a double extension | several script attachment rules |
| `link_cloud_storage_platform_hosting_malware_or_phishing_payload_f` | Payloads hosted on legitimate cloud storage platforms | broad existing coverage |
| `link_amazon_aws_typosquat_domain_delivering_malicious_payload` | Amazon and AWS typosquat domains delivering payloads | several typosquat rules |
| `body_onload_event_handler_with_base64_image_fragment_payload` | `onload=` handlers carrying Base64 image fragments, the OWAReaper pattern | several XSS delivery rules |
| `body_html_import_tag_splitting_xss` | `@import` tag splitting against webmail, the RoundPress and ZimReaper chain | one Zimbra header rule, different mechanism |
| `attachment_pdf_with_ai_generated_document_metadata_indicators` | PDFs whose metadata indicates machine generation | several PDF attachment rules |

Overlap was checked by keyword search against a clone of the public ruleset in October 2026. It is a starting point for comparison, not an exhaustive semantic review, and anyone considering one of these upstream should check it properly.

## Rules requiring a licensed backend

Five rules call Sublime-managed enrichment and will not evaluate without it.

| Rule | Backend |
|---|---|
| `attachment_pkpass_apple_wallet_pass_from_unsolicited_sender_with_suspic` | Link Analysis |
| `bec_real_estate_closing_wire_fraud` | Whois |
| `link_developer_recruitment_lure_with_fake_technical_assessment_or` | Link Analysis |
| `link_framer_hosted_page_with_credential_phishing_indicators` | Link Analysis |
| `link_microsoft_device_code_lure_in_email_body` | Link Analysis |

## Known issues

`link_developer_recruitment_lure_with_fake_technical_assessment_or` produced 26 false positives in testing, 24 of them technology newsletters. Adding a List-Unsubscribe header exclusion reduces that to 2, and the two remaining matches are legitimate recruiting mail the rule cannot distinguish from a lure. The rule is published as written, with the problem documented, rather than quietly patched. A rewrite that narrows at the sender rather than filtering on content afterwards is the better fix and is not done yet.

## Contributing

Corrections and false positive reports are welcome as issues or pull requests. If you run one of these against real attack traffic and it misses or misfires, that is the single most useful thing you can tell me.

## Licence

MIT. Take anything here, including upstream into the core ruleset, with or without attribution.
