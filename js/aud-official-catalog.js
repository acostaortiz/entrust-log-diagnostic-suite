// Auto-extracted from official Entrust IdentityGuard WebHelp manuals (IG 11.0 / 12.0 / 13.0)
window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG = {
  "AUD100": {
    "name": "First Time Initialization",
    "level": "INFO",
    "snmp": "",
    "desc": "First time initialization performed. Initial serial number set to {0}. Maximum number of users set to {1}. License expiry set to {2}. Where: · {0} is the initial serial number · {1} is the maximum number of users as defined by the license · {2} is the license expiry date",
    "category": "System Initialization audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/system_initialization_audit_messages.htm"
  },
  "AUD101": {
    "name": "Master User Shell Login",
    "level": "INFO",
    "snmp": "",
    "desc": "Login to supersh.",
    "category": "Master user audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_user_audit_messages.htm"
  },
  "AUD102": {
    "name": "Master User Shell Logout",
    "level": "INFO",
    "snmp": "",
    "desc": "Logout from supersh.",
    "category": "Master user audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_user_audit_messages.htm"
  },
  "AUD103": {
    "name": "Master User Shell Login Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Login failure.",
    "category": "Master user audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_user_audit_messages.htm"
  },
  "AUD104": {
    "name": "Master User Shell Re-login Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Relogin failure.",
    "category": "Master user audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_user_audit_messages.htm"
  },
  "AUD105": {
    "name": "Replica Initialization",
    "level": "INFO",
    "snmp": "",
    "desc": "Replica initialization performed.",
    "category": "System Initialization audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/system_initialization_audit_messages.htm"
  },
  "AUD106": {
    "name": "Service Start",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "{0} service started. {1} Where: · {0} is the name of the service. · {1} is the version information.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD107": {
    "name": "Service Stop",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "{0} service stopped. Where {0} is the name of the service.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD108": {
    "name": "Master User Password Change",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Password changed for master user {0}. Where {0} is the name of the master user.",
    "category": "Master user audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_user_audit_messages.htm"
  },
  "AUD109": {
    "name": "Master User Password Change Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Master password change failed.",
    "category": "Master user audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_user_audit_messages.htm"
  },
  "AUD110": {
    "name": "Service Start Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "{0} service startup failed. {1} Where: · {0} is the name of the service. · {1} is the version information.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD111": {
    "name": "System Upgrade Success",
    "level": "INFO",
    "snmp": "",
    "desc": "System upgrade success.",
    "category": "Upgrade audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/upgrade_audits.htm"
  },
  "AUD112": {
    "name": "System Upgrade Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "System upgrade failed.",
    "category": "Upgrade audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/upgrade_audits.htm"
  },
  "AUD113": {
    "name": "System Bind",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Bind key protection file.",
    "category": "Master key related audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_key_related_audit_messages.htm"
  },
  "AUD114": {
    "name": "System Unbind",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Unbind key protection file.",
    "category": "Master key related audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_key_related_audit_messages.htm"
  },
  "AUD115": {
    "name": "System Rebind",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "The key protection file binding has changed; run 'system bind' again.",
    "category": "Master key related audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_key_related_audit_messages.htm"
  },
  "AUD116": {
    "name": "Master Keys Update",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "The master keys have been updated. Reason: {0}. Where {0} is the update reason. The reason is the text included in the -reason parameter of the system keyupdate super shell command.",
    "category": "Master key related audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_key_related_audit_messages.htm"
  },
  "AUD117": {
    "name": "Master Keys Update With No Provided Reason",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "The master keys have been updated. No reason was provided.",
    "category": "Master key related audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_key_related_audit_messages.htm"
  },
  "AUD118": {
    "name": "Repository Update Status",
    "level": "INFO",
    "snmp": "",
    "desc": "Repository update status {0}. Where {0} is a report on the status of the repository update",
    "category": "Master key related audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/master_key_related_audit_messages.htm"
  },
  "AUD119": {
    "name": "Audit Message Test",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "A test audit message has been generated.",
    "category": "SNMP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/snmp_audit_messages.htm"
  },
  "AUD120": {
    "name": "Heartbeat Ping Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Heartbeat ping failed. Reason: {0} Where {0} is the reason the ping failed.",
    "category": "SNMP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/snmp_audit_messages.htm"
  },
  "AUD121": {
    "name": "Invalid Property Configuration",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "An error was detected parsing a property in the properties file {0}.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD122": {
    "name": "Invalid Token Configuration",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the token vendor properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD123": {
    "name": "Audit Database Configuration Error",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the audit database properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD124": {
    "name": "Out-Of-Band Delivery Configuration Error",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the OOB delivery properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD125": {
    "name": "Property Editor to Administration Service Connection Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Entrust IdentityGuard Properties Editor failed to connect to the Entrust IdentityGuard Administration Service.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD126": {
    "name": "Administration Interface to Administration Service Connection Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Entrust IdentityGuard Administration interface failed to connect to the Entrust IdentityGuard Administration Service.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD127": {
    "name": "Radius Proxy to Authentication Service Connection Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Entrust IdentityGuard Radius Proxy failed to connect to the Entrust IdentityGuard Authentication service.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD128": {
    "name": "Invalid SMTP Configuration",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the SMTP server properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD129": {
    "name": "JavaMail Upgrade",
    "level": "INFO",
    "snmp": "",
    "desc": "JavaMail OOB Delivery Mechanism {0} upgraded to use SMTP Server {1}. Where: · {0} is the name of the JavaMail Delivery Mechanism. · {1} is the name of the SMTP Server.",
    "category": "Upgrade audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/upgrade_audits.htm"
  },
  "AUD130": {
    "name": "Invalid Transaction Configuration",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the Transaction component properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD131": {
    "name": "Audit SMTP Configuration Error",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the audit SMTP properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD132": {
    "name": "HSM Connection Error",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Entrust IdentityGuard could not connect to the hardware security module.",
    "category": "Hardware Security Module (HSM) audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/hardware_security_module_hsm_audit_messages.htm"
  },
  "AUD133": {
    "name": "HSM Password Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "The password used to log in to to the hardware security module was updated.",
    "category": "Hardware Security Module (HSM) audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/hardware_security_module_hsm_audit_messages.htm"
  },
  "AUD134": {
    "name": "Invalid Smart Credential Delivery Configuration",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the Smart Credential delivery properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD135": {
    "name": "Invalid SMS Configuration",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the SMS server properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD136": {
    "name": "Invalid Digital ID Configuration Templates",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the DigitalId Config. Templates.",
    "category": "Digital ID configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/digital_id_configuration_audit_messages.htm"
  },
  "AUD137": {
    "name": "Invalid Smart Credential Applet Templates",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the Smart Credential Applet Templates.",
    "category": "Smart credential configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_configuration_audit_messages.htm"
  },
  "AUD138": {
    "name": "Invalid Smart Credential Definition Templates",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the Smart Credential Definition Templates.",
    "category": "Smart credential configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_configuration_audit_messages.htm"
  },
  "AUD139": {
    "name": "Invalid Smart Credential Layout Templates",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the Smart Credential Layout Templates.",
    "category": "Smart credential configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_configuration_audit_messages.htm"
  },
  "AUD146": {
    "name": "Invalid Biometric Vendor Configuration Templates",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Errors were detected in the biometric vendor properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD147": {
    "name": "Invalid External QA Configuration",
    "level": "ERROR",
    "snmp": "",
    "desc": "Errors were detected in the external QA properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD148": {
    "name": "Invalid Roaming Server Configuration",
    "level": "ERROR",
    "snmp": "",
    "desc": "Errors were detected in the Roaming Server properties in the properties file.",
    "category": "Property configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_configuration_audit_messages.htm"
  },
  "AUD150": {
    "name": "Repository Proxy to Authentication Service Connection Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Failed to connect to repository {0} with URL: {1} Where: · {0} is the name of the repository. · {1} is the URL to the repository.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD151": {
    "name": "High Availability Repository Failover",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Repository {0} connection failed to URL {1} switching to URL {2}. Where: · {0} is the name of the repository. · {1} is the URL to the repository that failed to connect. · {2} is the next URL that Entrust IdentityGuard will use to connect to the repository.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD152": {
    "name": "High Availability Primary Repository Restored",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "The primary connection has been restored for repository {0} to URL {1}. Where: · {0} is the name of the repository. · {1} is the URL to the repository.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD153": {
    "name": "High Availability Connection Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Failed to establish a connection to any supplied URLs for repository {0}. Where {0} is the name of the repository.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD154": {
    "name": "Connection Pool Exhausted",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Failed to obtain a connection to repository {0} from the connection pool due to pool exhaustion. Where {0} is the name of the repository.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD155": {
    "name": "Connection Pool 80 Percent Used",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Connection pool to repository {0} is 80 percent used. Where {0} is the name of the repository.",
    "category": "Service audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/service_audit_messages.htm"
  },
  "AUD1000": {
    "name": "User Created",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} created. Where: · {0} is the user ID. · {1} is the list of arguments set for the user. Includes the state of the user (Active or Suspended). Includes the DN and searchbase of the entry when using an LDAP repository.",
    "category": "User audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_audit_messages.htm"
  },
  "AUD1001": {
    "name": "User Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} deleted. Where {0} is the user ID.",
    "category": "User audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_audit_messages.htm"
  },
  "AUD1002": {
    "name": "User Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} updated. {1} is the list of arguments set for the user. Where: · {0} is the user ID. · {1} is the list of arguments set for the user. Includes the state of the user (Active or Suspended).",
    "category": "User audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_audit_messages.htm"
  },
  "AUD1004": {
    "name": "User Challenge Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Challenge for user {0} deleted. Where {0} is the user ID.",
    "category": "User audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_audit_messages.htm"
  },
  "AUD2000": {
    "name": "User Card Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Card {1} has been created for user {0}. {2} Where: · {0} is the user ID. · {1} is the card serial number. · {2} is the list of arguments set for the user card.",
    "category": "User card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_card_audit_messages.htm"
  },
  "AUD2001": {
    "name": "User Card superseded",
    "level": "INFO",
    "snmp": "",
    "desc": "Card {1} for user {0} has been superseded by card {2}. {3} Where: · {0} is the user ID. · {1} is the serial number of superseded card. · {2} is the serial number of new card. · {3} is the list of arguments for the supersede operation including the supersede date.",
    "category": "User card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_card_audit_messages.htm"
  },
  "AUD2002": {
    "name": "User Card Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Card {1} for user {0} has been deleted. Where: · {0} is the user ID. · {1} is the card serial number.",
    "category": "User card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_card_audit_messages.htm"
  },
  "AUD2003": {
    "name": "User Card Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Card {1} for user {0} has been updated. {2} Where: · {0} is the user ID. · {1} is the serial number of the user card. · {2} is the list of arguments for the user card.",
    "category": "User card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_card_audit_messages.htm"
  },
  "AUD2004": {
    "name": "User Card Unassigned",
    "level": "INFO",
    "snmp": "",
    "desc": "Card with serial number {1} for user {0} has been unassigned. {2} Where: · {0} is the user ID. · {1} is the serial number of user card. · {2} is the list of arguments for the user card.",
    "category": "User card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_card_audit_messages.htm"
  },
  "AUD2005": {
    "name": "User Card Delivered",
    "level": "INFO",
    "snmp": "",
    "desc": "Card {1} for user {0} has been delivered to {3} using delivery configuration {2}. Where: · {0} is the user ID. · {1} is the serial number of user card. · {2} is the delivery configuration used.",
    "category": "User card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_card_audit_messages.htm"
  },
  "AUD2100": {
    "name": "Single Preproduced Card Creation",
    "level": "INFO",
    "snmp": "",
    "desc": "Preproduced card {1} has been created in group {0}. {2} Where: · {0} is the group. · {1} is the serial number of the card. · {2} is the list of arguments set for the new card.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2101": {
    "name": "Multiple Preproduced Card Creation Started",
    "level": "INFO",
    "snmp": "",
    "desc": "Start creating {1} preproduced cards with serial numbers from {2} to {3} in group {0}. {4} Where: · {0} is the group. · {1} is the number of cards that are going to be created. · {2} is the start range for serial numbers of the new cards. · {3} is the end range for serial numbers of the new cards. · {4} is the list of arguments set for the new card.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2102": {
    "name": "Multiple Preproduced Card Creation Completed",
    "level": "INFO",
    "snmp": "",
    "desc": "Created {1}/{2} preproduced cards with serial numbers ranging from {3} to {4} in group {0}. Where: · {0} is the group. · {1} is the number of cards actually created. · {2} is the number of cards that were supposed to be created. · {3} start range for serial numbers of the new cards. · {4} end range for serial numbers of the new cards.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2103": {
    "name": "Preproduced Card Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Preproduced card with serial number {0} has been deleted. Where {0} is the serial number of the card.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2104": {
    "name": "Preproduced Card Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Preproduced card {0} has been updated. {1} Where: · {0} is the serial number of the card. · {1} is the list of arguments set for the new card.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2105": {
    "name": "Preproduced Card Assigned",
    "level": "INFO",
    "snmp": "",
    "desc": "Preproduced card {0} has been assigned to user {1}. {2} Where: · {0} is the serial number of the card. · {1} is the user ID. · {2} is the list of arguments set for the new card.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2106": {
    "name": "Preproduced Card Imported",
    "level": "INFO",
    "snmp": "",
    "desc": "Preproduced card {1} has been imported in to group {0}. Where: · {0} is the group. · {1} is the serial number of the card.",
    "category": "Preproduced card audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/preproduced_card_audit_messages.htm"
  },
  "AUD2200": {
    "name": "Unassigned Token Loaded",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {0} {1} has been loaded. {2} Where: · {0} is the token vendor. · {1} is the serial number of the token · {2} is the list of arguments set for the token.",
    "category": "Unassigned token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_token_audit_messages.htm"
  },
  "AUD2201": {
    "name": "Unassigned Token Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {0} {1} has been deleted. Where: · {0} is the token vendor. · {1} is the serial number of the token",
    "category": "Unassigned token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_token_audit_messages.htm"
  },
  "AUD2202": {
    "name": "Unassigned Token Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {0} {1} has been updated. {2} Where: · {0} is the token vendor. · {1} is the serial number of the token · {2} is the list of arguments set for the token.",
    "category": "Unassigned token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_token_audit_messages.htm"
  },
  "AUD2203": {
    "name": "Unassigned Token Loading Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Unable to load token {0} {1}. Where: · {0} is the token vendor. · {1} is the serial number of the token",
    "category": "Unassigned token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_token_audit_messages.htm"
  },
  "AUD2300": {
    "name": "User Token Assigned",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {0} {1} has been assigned to user {2}. {3} Where: · {0} is the token vendor. · {1} is the serial number of the token. · {2} is the user ID. · {3} is the list of arguments set for the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2301": {
    "name": "User Token Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {1} {2} for user {0} has been deleted. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2302": {
    "name": "User Token Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {1} {2} for user {0} has been updated. {3} Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token. · {3} is the list of arguments set for the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2303": {
    "name": "User Token Unassigned",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {1} {2} for user {0} has been unassigned. {3} Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token. · {3} is the list of arguments set for the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2304": {
    "name": "User Token Unlocked",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {1} {2} for user {0} has been unlocked. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2305": {
    "name": "User Token Activated",
    "level": "INFO",
    "snmp": "",
    "desc": "Activation codes for token {1} {2} for user {0} have been generated. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2306": {
    "name": "User Token Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {0} {1} has been created for user {2}. {3} Where: · {0} is the token vendor. · {1} is the serial number of the token. · {2} is the user ID. · {3} is the list of arguments set for the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2307": {
    "name": "User Token Activation Completed",
    "level": "INFO",
    "snmp": "",
    "desc": "Token {1} {2} for user {0} has been successfully activated. {3} Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token. · {3} is the list of arguments set for the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2308": {
    "name": "User Token Transaction Delivery Successful",
    "level": "INFO",
    "snmp": "",
    "desc": "Transaction details for token {1} {2} for user {0} have been successfully delivered. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2309": {
    "name": "User Token Delivery Failed",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Failed delivery of transaction details for token {1} {2} for user {0}. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2310": {
    "name": "User Token Transaction Validate Failed",
    "level": "ERROR",
    "snmp": "",
    "desc": "Transaction failed validation for token {1} {2} for user {0}. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2311": {
    "name": "User Token Callback Validate Failed",
    "level": "ERROR",
    "snmp": "",
    "desc": "Transaction failed validation for token {1} {2} for user {0}. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the serial number of the token. · {3} is the URL of the failed callback.",
    "category": "User token audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_token_audit_messages.htm"
  },
  "AUD2350": {
    "name": "User Smart Credential Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} has been created for user {0}. {2} Where: · {0} is the user ID. · {1} is the smart credential ID. · {2} is the list of arguments set for the smart credential.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2351": {
    "name": "User Smart Credential Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been deleted. Where: · {0} is the user ID. · {1} is the smart credential ID.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2352": {
    "name": "User Smart Credential Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been updated. {2} Where: · {0} is the user ID. · {1} is the smart credential ID. · {2} is the list of arguments set for the smart credential.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2353": {
    "name": "User Smart Credential Unblocked",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been unblocked. Where: · {0} is the user ID. · {1} is the smart credential ID.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2354": {
    "name": "User Smart Credential Issued",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been issued to print module {2}. Where: · {0} is the user ID. · {1} is the smart credential ID. · {2} is the print module.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2355": {
    "name": "User Smart Credential Approved",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been approved. Where: · {0} is the user ID. · {1} is the smart credential ID.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2356": {
    "name": "User Smart Credential Sealed",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been sealed. Where: · {0} is the user ID. · {1} is the smart credential ID.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2357": {
    "name": "User Smart Credential Delivered",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been delivered using delivery configuration {2}. Where: · {0} is the user ID. · {1} is the smart credential ID. · {2} is the delivery configuration.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2358": {
    "name": "User Smart Credential Unassigned",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} with Serial Number {2} for user {0} has been unassigned. {3} Where: · {0} is the user ID. · {1} is the smart credential ID. · {2} is the serial number of the smart credential. · {3} is the list of arguments set for the smart credential.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2359": {
    "name": "User Smart Credential PACS Registered.",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been registered to PACS. {2} Where: · {0} is the user ID. · {1} is the smart credential ID. · {3} is the PACS parameters.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2360": {
    "name": "User Smart Credential PACS Suspended",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential {1} for user {0} has been suspended from PACS. {2} Where: · {0} is the user ID. · {1} is the smart credential ID. · {3} is the PACS parameters.",
    "category": "User smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_audits.htm"
  },
  "AUD2372": {
    "name": "User Smart Credential Expiry Notify Delivery Success",
    "level": "INFO",
    "snmp": "",
    "desc": "Expiry notification for smart credential {1} for user {0} has been successfully delivered using delivery configuration {2}. Where: · {0} is the user ID. · {1} is the delivery ID. · {2} is the name of the delivery configuration.",
    "category": "User smart credential expiry notification delivery audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_expiry_notification_delivery_audit.htm"
  },
  "AUD2373": {
    "name": "User Smart Credential Expiry Notify Delivery Success Final",
    "level": "INFO",
    "snmp": "",
    "desc": "Final expiry notification for smart credential {1} for user {0} has been successfully delivered using delivery configuration {2}. Where: · {0} is the user ID. · {1} is the delivery ID. · {2} is the name of the delivery configuration.",
    "category": "User smart credential expiry notification delivery audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_expiry_notification_delivery_audit.htm"
  },
  "AUD2374": {
    "name": "User Smart Credential Expiry Notify Delivery Success Final",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Failed to deliver an expiry notification for smart credential {1} for user {0} has been successfully delivered using delivery configuration {2}. Where: · {0} is the user ID. · {1} is the delivery ID. · {2} is the name of the delivery configuration.",
    "category": "User smart credential expiry notification delivery audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_smart_credential_expiry_notification_delivery_audit.htm"
  },
  "AUD2380": {
    "name": "Unassigned Smart Credential Loaded",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart credential {0} has been loaded. {1} Where: · {0} is the serial number of the smart credential. · {1} is the list of arguments set for the smart credential.",
    "category": "Unassigned smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_smart_credential_audits.htm"
  },
  "AUD2381": {
    "name": "Unassigned Smart Credential Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart credential {0} has been deleted. Where {0} is the serial number of the smart credential.",
    "category": "Unassigned smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_smart_credential_audits.htm"
  },
  "AUD2382": {
    "name": "Unassigned Smart Credential Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart credential {0} has been updated. {1} Where: · {0} is the serial number of the smart credential. · {1} is the list of arguments set for the smart credential.",
    "category": "Unassigned smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_smart_credential_audits.htm"
  },
  "AUD2383": {
    "name": "Unassigned Smart Credential Load Failed",
    "level": "INFO",
    "snmp": "",
    "desc": "Unable to load smart credential {0}. Where {0} is the serial number of the smart credential.",
    "category": "Unassigned smart credential audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/unassigned_smart_credential_audits.htm"
  },
  "AUD2400": {
    "name": "Machine Secret Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Machine secret {1} has been added to user {0}. Where: · {0} is the user ID. · {1} is the machine secret label.",
    "category": "Machine secret audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/machine_secret_audit_messages.htm"
  },
  "AUD2401": {
    "name": "Machine Secret Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Machine secret {1} deleted from user {0}. Where: · {0} is the user ID. · {1} is the machine secret label.",
    "category": "Machine secret audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/machine_secret_audit_messages.htm"
  },
  "AUD2402": {
    "name": "Machine Secret Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Machine secret {1} for user {0} was updated. {2}. Where: · {0} is the user ID. · {1} is the machine secret label. · {2} is a list of arguments indicating label or application data was changed.",
    "category": "Machine secret audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/machine_secret_audit_messages.htm"
  },
  "AUD2450": {
    "name": "User Digital ID Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {0} has been created for user {1}. {2} Where: · {0} is the distinguished name of the digital ID. · {1} is the user ID. · {2} is a list of arguments set for the digital ID.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2451": {
    "name": "User Digital ID Recovered",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {0} has been recovered for user {1}. {2} Where: · {0} is the distinguished name of the digital ID. · {1} is the user ID. · {2} is a list of arguments set for the digital ID.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2452": {
    "name": "User Digital ID Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {1} for user {0} has been deleted. Where: · {0} is the user ID. · {1} is the distinguished name of the digital ID.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2453": {
    "name": "User Digital ID Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {1} for user {0} has been updated. {2} Where: · {0} is the user ID. · {1} is the distinguished name of the digital ID. · {2} is a list of arguments set for the digital ID.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2454": {
    "name": "User Digital ID Canceled",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {1} for user {0} has been canceled. {2} certificates revoked. Where: · {0} is the user ID. · {1} is the distinguished name of the digital ID. · {2} is the number of certificates that were revoked.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2455": {
    "name": "User Digital ID Hold",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {1} for user {0} has been put on hold. {2} certificates put on hold. Where: · {0} is the user ID. · {1} is the distinguished name of the digital ID. · {2} is the number of certificates that were put on hold.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2456": {
    "name": "User Digital ID Unhold",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id {1} for user {0} has been removed from hold. {2} certificates removed from hold. Where: · {0} is the user ID. · {1} is the distinguished name of the digital ID. · {2} is the number of certificates that were taken off hold.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2457": {
    "name": "User Digital ID Cancel Failed",
    "level": "ERROR",
    "snmp": "",
    "desc": "Error trying to cancel digital id {1} for user {0}. Where: · {0} is the user ID. · {1} is the distinguished name of the digital ID.",
    "category": "User digital ID audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_digital_id_audits.htm"
  },
  "AUD2500": {
    "name": "User Preference Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Preference {1} has been added to user {0}. Where: · {0} is the user ID. · {1} is the preference name.",
    "category": "User preference audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_preference_audit_messages.htm"
  },
  "AUD2501": {
    "name": "User Preference Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Preference {1} deleted from user {0}. Where: · {0} is the user ID. · {1} is the preference name.",
    "category": "User preference audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_preference_audit_messages.htm"
  },
  "AUD2502": {
    "name": "User Preference Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Preference {1} for user {0} was updated. Where: · {0} is the user ID. · {1} is the preference name.",
    "category": "User preference audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_preference_audit_messages.htm"
  },
  "AUD2600": {
    "name": "User Biometric Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Biometric {0} has been created for user {1}. {2} Where: · {0} is the vendor. · {1} is the user ID. · {2} is the list of arguments set for the biometric.",
    "category": "User biometric audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_biometric_audit_messages.htm"
  },
  "AUD2601": {
    "name": "User Biometric Deleted from User",
    "level": "INFO",
    "snmp": "",
    "desc": "Biometric {1} for user {0} has been deleted. Where: · {0} is the user ID. · {1} is the vendor of the deleted biometric.",
    "category": "User biometric audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_biometric_audit_messages.htm"
  },
  "AUD2602": {
    "name": "User Biometric Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Biometric {1} for user {0} has been updated. {2} Where: · {0} is the user ID. · {1} is the vendor of the biometric. · {2} is the list of arguments for the user biometric that has been updated.",
    "category": "User biometric audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_biometric_audit_messages.htm"
  },
  "AUD2603": {
    "name": "User Biometric Enrolled",
    "level": "INFO",
    "snmp": "",
    "desc": "Biometric {1} for user {0} has been enrolled. Where: · {0} is the user ID. · {1} is the vendor of biometric.",
    "category": "User biometric audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_biometric_audit_messages.htm"
  },
  "AUD2604": {
    "name": "User Biometric Enroll Failed",
    "level": "INFO",
    "snmp": "",
    "desc": "Biometric {1} for user {0} has been failed enrollment. Where: · {0} is the user ID. · {1} is the vendor of the biometric.",
    "category": "User biometric audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_biometric_audit_messages.htm"
  },
  "AUD3000": {
    "name": "Temporary PIN Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Temporary PIN created for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the temporary PIN.",
    "category": "Temporary PIN audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/temporary_pin_audit_messages.htm"
  },
  "AUD3001": {
    "name": "Temporary PIN Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Temporary PIN deleted for user {0}. Where {0} is the user ID.",
    "category": "Temporary PIN audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/temporary_pin_audit_messages.htm"
  },
  "AUD3002": {
    "name": "Temporary PIN Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Temporary PIN updated for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the temporary PIN.",
    "category": "Temporary PIN audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/temporary_pin_audit_messages.htm"
  },
  "AUD3003": {
    "name": "OTP Created",
    "level": "INFO",
    "snmp": "",
    "desc": "One time password with index {1} created for user {0}. {2} Where: · {0} is the user ID. · {1} is the OTP index of the new OTP. · {2} is the list of arguments set for the OTP.",
    "category": "OTP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/otp_audit_messages.htm"
  },
  "AUD3004": {
    "name": "OTP Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "One time password with index {1} deleted for user {0}. Where: · {0} is the user ID. · {1} is the OTP index of the new OTP.",
    "category": "OTP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/otp_audit_messages.htm"
  },
  "AUD3005": {
    "name": "PVN Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Personal Verification Number created for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the PVN.",
    "category": "PVN audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/pvn_audit_messages.htm"
  },
  "AUD3006": {
    "name": "PVN Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Personal Verification Number deleted for user {0}. Where {0} is the user ID.",
    "category": "PVN audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/pvn_audit_messages.htm"
  },
  "AUD3007": {
    "name": "PVN Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Personal Verification Number updated for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the PVN.",
    "category": "PVN audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/pvn_audit_messages.htm"
  },
  "AUD3008": {
    "name": "OTP Delivery Success",
    "level": "INFO",
    "snmp": "",
    "desc": "One time password delivered to user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the OTP.",
    "category": "OTP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/otp_audit_messages.htm"
  },
  "AUD3009": {
    "name": "OTP Modified",
    "level": "INFO",
    "snmp": "",
    "desc": "One time password with index {1} modified for user {0}. {2} Where: · {0} is the user ID. · {1} is the OTP index of the OTP. · {2} is the list of arguments set for the OTP.",
    "category": "OTP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/otp_audit_messages.htm"
  },
  "AUD3010": {
    "name": "OTP Delivery Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "One time password delivery failed for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the OTP.",
    "category": "OTP audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/otp_audit_messages.htm"
  },
  "AUD3100": {
    "name": "Contact Information Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Contact info {1} has been created for user {0}. {2} Where: · {0} is the user ID. · {1} is the label of the contact information. · {2} is the list of arguments set for the contact information.",
    "category": "Contact information audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/contact_information_audit_messages.htm"
  },
  "AUD3101": {
    "name": "Contact Information Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "The following contact infos have been deleted for user {0}. {1} Where: · {0} is the user ID. · {1} is list of contact information labels.",
    "category": "Contact information audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/contact_information_audit_messages.htm"
  },
  "AUD3102": {
    "name": "Contact Information Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Contact info {1} has been updated for user {0}. {2} Where: · {0} is the user ID. · {1} is the label of the contact information. · {2} is the list of arguments set for the contact information.",
    "category": "Contact information audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/contact_information_audit_messages.htm"
  },
  "AUD3200": {
    "name": "Password Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Password value created for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the password.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3201": {
    "name": "Password Meta Data Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Password information modified for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the password.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3202": {
    "name": "Password Changed",
    "level": "INFO",
    "snmp": "",
    "desc": "Password Authentication API password change for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the password.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3203": {
    "name": "Password Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Password deleted for user {0}. {1} Where: · {0} is the user ID. · {1} is the list of arguments set for the password.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3206": {
    "name": "Password Change Failed",
    "level": "ERROR",
    "snmp": "",
    "desc": "User attempted password change failed for user {0}. Where {0} is the user ID.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3207": {
    "name": "Disallowed Password File Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Problem occurred reading disallowed password file.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3208": {
    "name": "Disallowed Password File Success",
    "level": "INFO",
    "snmp": "",
    "desc": "Success loading disallowed password file {0}. Where {0} is the file name.",
    "category": "Password audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/password_audit_messages.htm"
  },
  "AUD3300": {
    "name": "Federation Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Federation type {1} with partner id {2} has been assigned to user {0}. Where: · {0} is the user ID. · {1} is the federation type. · {2} is the partner ID.",
    "category": "User federation audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_federation_audit_messages.htm"
  },
  "AUD3301": {
    "name": "Federation deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Federation type {1} with partner id {2} for user {0} has been deleted. Where: · {0} is the user ID. · {1} is the federation type. · {2} is the partner ID.",
    "category": "User federation audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_federation_audit_messages.htm"
  },
  "AUD3302": {
    "name": "Federation Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Federation type {1} with partner id {2} for user {0} has been updated. Where: · {0} is the user ID. · {1} is the federation type. · {2} is the partner ID.",
    "category": "User federation audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_federation_audit_messages.htm"
  },
  "AUD4003": {
    "name": "Administrator Login",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator logged in.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4004": {
    "name": "Administrator Logout",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator logged out.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4005": {
    "name": "Administrator Failed Login And Was Locked Out",
    "level": "ERROR",
    "snmp": "",
    "desc": "Administrator has been locked out until {0}. Where {0} is the time at which the administrator will unlock.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4006": {
    "name": "Administrator Login For Operation",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator logged in to perform operation {0}. Where {0} is the operation that the administrator is performing.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4007": {
    "name": "Administrator Permission Denied",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator attempted to perform an operation but their roles did not permit it.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4008": {
    "name": "Administrator Permission Denied Not Self",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator attempted to perform an operation on another user. Operation is only allowed to be performed on self.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4009": {
    "name": "Administrator Authentication Attempt With Invalid Password",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} entered an invalid password. Where {0} is the administrator name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4010": {
    "name": "Administrator Authentication Attempt While Locked Out",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} attempted to access the administration service, but their account is locked. Where {0} is the administrator name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4011": {
    "name": "Administrator Has No Password",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted to access the administration service, but they do not have a password. Where {0} is the user name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4012": {
    "name": "Administrator Has No Roles",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted to access the administration service, but they do not have any roles that grant administrative privileges. Where {0} is the user name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4013": {
    "name": "Administrator Authentication Attempt While Not Active",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} attempted to access the administration service, but their account is not active. Where {0} is the administrator name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4014": {
    "name": "Administrator Authentication Attempt While Disabled in Repository",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} attempted to access the administration service, but their account in the repository is disabled. Where {0} is the administrator name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4015": {
    "name": "Administrator Authentication Attempt While Expired in Repository",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} attempted to access the administration service, but their account in the repository is expired. Where {0} is the administrator name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4016": {
    "name": "Administrator Failed External Authentication",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} failed external authentication. Where {0} is the administrator name.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4017": {
    "name": "Administrator Failed Certificate Authentication",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted to access the administration service, but failed certificate authentication.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4018": {
    "name": "Administrator Has No Delegation Policy",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} attempted to access the administration service by delegation, but their policy does not permit it. An administrator attempted to log in to the Administration service but the account is orphaned in the repository.",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD4019": {
    "name": "Administrator Authentication Attempt While orphaned in Repository",
    "level": "INFO",
    "snmp": "",
    "desc": "Administrator {0} attempted to access the administration service, but their account in the repository is orphaned. · {0} is the policy name · {1} is a list of settings updated and their new values",
    "category": "Administrator audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/administrator_audit_messages.htm"
  },
  "AUD5000": {
    "name": "Card Specification Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Card specification {0} updated: {1} Where: · {0} is the policy name. · {1} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5001": {
    "name": "Temporary PIN Specification Policy Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Temporary PIN specification {0} updated: {1} Where: · {0} is the policy name. · {1} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5002": {
    "name": "Password Policy Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Password policy {0} updated: {1} Where: · {0} is the policy name. · {1} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5003": {
    "name": "License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "License updated: {0} Where {0} is the policy name.",
    "category": "License audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/license_audit_messages.htm"
  },
  "AUD5004": {
    "name": "License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of users reset from {0} to {1}. Where: · {0} is the number of users in the license count. · {1} is the number of users found in the repository.",
    "category": "License audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/license_audit_messages.htm"
  },
  "AUD5005": {
    "name": "License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of users {0} is nearing license limit {1}. Where: · {0} is the current number of users. · {1} is the license limit.",
    "category": "License audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/license_audit_messages.htm"
  },
  "AUD5006": {
    "name": "License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of users {0} is over license limit {1}. Where: · {0} is the current number of users. · {1} is the license limit.",
    "category": "License audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/license_audit_messages.htm"
  },
  "AUD5007": {
    "name": "License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "License is near expiry date {0}. Where {0} is the license expiry date.",
    "category": "License audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/license_audit_messages.htm"
  },
  "AUD5008": {
    "name": "License Past Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "License is over expiry date {0}. Where {0} is the license expiry date.",
    "category": "License audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/license_audit_messages.htm"
  },
  "AUD5009": {
    "name": "Role Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Role {0} created: {1} Where: · {0} is the role name. · {1} is the list of arguments set for the role.",
    "category": "Role audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/role_audit_messages.htm"
  },
  "AUD5010": {
    "name": "Role Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Role {0} updated: {1} Where: · {0} is the role name. · {1} is the list of arguments set for the role.",
    "category": "Role audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/role_audit_messages.htm"
  },
  "AUD5011": {
    "name": "Role Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Role {0} deleted. Where {0} is the role name.",
    "category": "Role audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/role_audit_messages.htm"
  },
  "AUD5015": {
    "name": "User Specification Policy Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "User specification {0} updated: {1} Where: · {0} is the policy name. · {1} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5016": {
    "name": "Global Policy Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Global policy updated: {0} Where {0} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5017": {
    "name": "Group Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Group {0} created: {1} Where: · {0} is the group name. · {1} is a list of settings updated and their new values.",
    "category": "Group audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/group_audit_messages.htm"
  },
  "AUD5018": {
    "name": "Group Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Group {0} updated: {1} Where: · {0} is the group name. · {1} is a list of settings updated and their new values.",
    "category": "Group audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/group_audit_messages.htm"
  },
  "AUD5019": {
    "name": "Group Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Group {0} deleted. Where {0} is the group name.",
    "category": "Group audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/group_audit_messages.htm"
  },
  "AUD5020": {
    "name": "Policy Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Policy {0} created: {1} Where: · {0} is the policy name. · {1} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5021": {
    "name": "Policy Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Policy {0} updated: {1} Where: · {0} is the policy name. · {1} is the list of settings updated and their new values.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5022": {
    "name": "Policy Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Policy {0} deleted. Where {0} is the policy name.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5025": {
    "name": "IP Blacklist Additions",
    "level": "INFO",
    "snmp": "",
    "desc": "IP addresses from {0} to {1} added to IP blacklist. Where: · {0} is the first IP address in the range of IP addresses. · {1} is the last IP address in the range of IP addresses.",
    "category": "IP blacklist audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/ip_blacklist_audit_messages.htm"
  },
  "AUD5026": {
    "name": "IP Blacklist Deletions",
    "level": "INFO",
    "snmp": "",
    "desc": "IP addresses from {0} to {1} removed from IP blacklist. Where: · {0} is the first IP address in the range of IP addresses. · {1} is the last IP address in the range of IP addresses.",
    "category": "IP blacklist audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/ip_blacklist_audit_messages.htm"
  },
  "AUD5027": {
    "name": "IP Blacklist Completely Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "All IP addresses removed from IP blacklist.",
    "category": "IP blacklist audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/ip_blacklist_audit_messages.htm"
  },
  "AUD5029": {
    "name": "System Role Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Built-in system role {0} created. Where {0} is the role name.",
    "category": "Role audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/role_audit_messages.htm"
  },
  "AUD5030": {
    "name": "Partition Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Partition {0} created: {1} Where: · {0} is the partition name. · {1} is the list of arguments set for the partition.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5031": {
    "name": "Partition Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Partition {0} updated: {1} Where: · {0} is the partition name. · {1} is the list of arguments set for the partition.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5032": {
    "name": "Partition Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Partition {0} deleted. Where {0} is the partition name.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5033": {
    "name": "Partition Count Reset",
    "level": "INFO",
    "snmp": "",
    "desc": "Number of users in partition {0} reset from {1} to {2}. Where: · {0} is the partition name. · {1} is the number of users in the partition. · {2} is the number of users found in the repository assigned to the partition.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5034": {
    "name": "Partition Count Mismatch",
    "level": "WARN",
    "snmp": "",
    "desc": "Number of users in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the partition name. · {1} is the number of users in the partition. · {2} is the number of users found in the repository assigned to the partition.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5035": {
    "name": "Partition User Limit",
    "level": "WARN",
    "snmp": "",
    "desc": "Number of users that can be created in partition {0} is {1} percent used. Where: · {0} is the partition name. · {1} is the percentage of user numbers assigned to the partition that have been used.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5036": {
    "name": "Partition Card Limit",
    "level": "WARN",
    "snmp": "",
    "desc": "Number of cards that can be created in partition {0} is {1} percent used. Where: · {0} is the partition name. · {1} is the percentage of card serial numbers assigned to the partition that have been used.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5037": {
    "name": "Partition User Threshold",
    "level": "ERROR",
    "snmp": "",
    "desc": "No more users can be created in partition {0} because all user numbers have been used. Where {0} is the partition name.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5038": {
    "name": "Partition Card Threshold",
    "level": "ERROR",
    "snmp": "",
    "desc": "No more cards can be created in partition {0} because all card serial numbers have been used. Where {0} is the partition name.",
    "category": "Partition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/partition_audit_messages.htm"
  },
  "AUD5039": {
    "name": "Policy Moved",
    "level": "INFO",
    "snmp": "",
    "desc": "All policy, group, role, partition, transaction certificate and IP blacklist definitions were moved from repository {0} to repository {1}. Where: · {0} is the name of the repository where the data was moved from. · {1} is the name of the repository where the data was moved to.",
    "category": "Policy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/policy_audit_messages.htm"
  },
  "AUD5040": {
    "name": "Transaction Certificate Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Transaction certificate {0} created: {1} Where: · {0} is the name of the transaction certificate. · {1} is the list of arguments set for the transaction certificate.",
    "category": "Transaction certificate audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_certificate_audit_messages.htm"
  },
  "AUD5041": {
    "name": "Transaction Certificate Imported",
    "level": "INFO",
    "snmp": "",
    "desc": "Transaction certificate {0} imported: {1} Where: · {0} is the name of the transaction certificate. · {1} is the list of arguments set for the transaction certificate. · {1} is the list of arguments set for the transaction certificate import",
    "category": "Transaction certificate audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_certificate_audit_messages.htm"
  },
  "AUD5042": {
    "name": "Transaction Certificate Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Transaction certificate {0} updated: {1} Where: · {0} is the name of the transaction certificate. · {1} is the list of arguments set for the transaction certificate.",
    "category": "Transaction certificate audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_certificate_audit_messages.htm"
  },
  "AUD5043": {
    "name": "Transaction Certificate Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Transaction certificate {0} deleted. Where {0} is the name of the transaction certificate.",
    "category": "Transaction certificate audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_certificate_audit_messages.htm"
  },
  "AUD5044": {
    "name": "Token License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Token license updated: {0} Where {0} is the expiry date and number of soft tokens allowed.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5045": {
    "name": "Token License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed tokens reset from {0} to {1}. Where: · {0} is the number of tokens in the Entrust IdentityGuard license count. · {1} is the number of licensed tokens found in the repository.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5046": {
    "name": "Token License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed tokens {0} is nearing license limit {1}. Where: · {0} is the current number of licensed tokens. · {1} is the license limit.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5047": {
    "name": "Token License At Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed tokens has reached the license limit {0}. Where {0} is the current number of licensed tokens.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5048": {
    "name": "Token License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of licensed tokens {0} is over license limit {1}. Where: · {0} is the current number of licensed tokens. · {1} is the license limit.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5049": {
    "name": "Token License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Token license is near expiry date {0}. Where {0} is the token license expiry date.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5050": {
    "name": "Report Invalid Configuration",
    "level": "ERROR",
    "snmp": "",
    "desc": "Errors were detected in the report definition properties in the properties file.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5051": {
    "name": "Report Requested",
    "level": "INFO",
    "snmp": "",
    "desc": "Report name {0} with id {1} has been added to the report generation queue by user {2}. Where: · {0} is the name of the report. · {1} is the report ID. · {2} is the administrator’s user ID.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5052": {
    "name": "Report Generated",
    "level": "INFO",
    "snmp": "",
    "desc": "Report name {0} with id {1} has been generated for user {2}. Where: · {0} is the name of the report. · {1} is the report ID. · {2} is the administrator’s user ID.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5053": {
    "name": "Report Truncated",
    "level": "INFO",
    "snmp": "",
    "desc": "Report name {0} with id {1} has been generated for user {2} but was truncated. Where: · {0} is the name of the report. · {1} is the report ID. · {2} is the administrator’s user ID.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5054": {
    "name": "Report Failed",
    "level": "INFO",
    "snmp": "",
    "desc": "Report name {0} with id {1} failed to be generated for user {2}. Where: · {0} is the name of the report. · {1} is the report ID. · {2} is the administrator’s user ID.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5055": {
    "name": "Report Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Report name {0} with id {1} has been deleted from the system by user {2}. Where: · {0} is the name of the report. · {1} is the report ID. · {2} is the administrator’s user ID.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5056": {
    "name": "Report Auto Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Report name {0} with id {1} has been automatically removed from the system due to a new report being generated in its place for user {2}. Where: · {0} is the name of the report. · {1} is the report ID. · {2} is the administrator’s user ID.",
    "category": "Reporting audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/reporting_audit_messages.htm"
  },
  "AUD5057": {
    "name": "Token License Over Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Token license is past expiry date {0}. Where {0} is the token license expiry date.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5058": {
    "name": "Token License Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Token license was deleted.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5059": {
    "name": "Partition Token Count Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed tokens in partition {0} reset from {1} to {2}. Where: · {0} is the name of the partition. · {1} is the number of licensed tokens in the partition. · {2} is the number of licensed tokens assigned to the partition that were found in the repository.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5060": {
    "name": "Partition Token Count MisMatch",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed tokens in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the name of the partition. · {1} is the number of licensed tokens in the partition. · {2} is the number of licensed tokens assigned to the partition that were found in the repository.",
    "category": "Soft token license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/soft_token_license_audit_messages.htm"
  },
  "AUD5070": {
    "name": "Smart Credential License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Smart Credential License updated: {0} Where {0} is details about the license update.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5071": {
    "name": "Smart Credential License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials reset from {0} to {1}. Where: · {0} is the number of smart credentials in the license count. · {1} is the number of licensed smart credentials found in repository.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5072": {
    "name": "Smart Credential License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials {0} is nearing license limit {1}. Where: · {0} is the current number of licensed smart credentials. · {1} is the smart credential license limit.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5073": {
    "name": "Smart Credential License At Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials has reached the license limit {0}. Where {o} is the smart credential license limit.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5074": {
    "name": "Smart Credential License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials {0} is over license limit {1}. Where: · {0} is the current number of licensed smart credentials. · {1} is the smart credential license limit.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5075": {
    "name": "Smart Credential License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Smart Credential license is near expiry date {0}. Where {0} is smart credential license expiry date.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5076": {
    "name": "Smart Credential License Over Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Smart Credential license is past expiry date {0}. Where {0} is smart credential license expiry date.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5077": {
    "name": "Smart Credential License Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential license was deleted.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5078": {
    "name": "Partition Smart Credential Count Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials in partition {0} reset from {1} to {2}. Where: · {0} is the name of the partition. · {1} is the number of licensed smart credentials in the partition. · {2} is the number of licensed smart credentials assigned to the partition that were found in the repository.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5079": {
    "name": "Partition Smart Credential Count Mismatch",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the name of the partition. · {1} is the number of licensed smart credentials in the partition. · {2} is the number of licensed smart credentials assigned to the partition that were found in the repository.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5080": {
    "name": "Mobile Smart Credential License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Mobile Smart Credential License updated: {0} Where {0} is details about the license update.",
    "category": "Smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_license_audit_messages.htm"
  },
  "AUD5081": {
    "name": "Mobile Smart Credential License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed mobile smart credentials reset from {0} to {1}. Where: · {0} is the number of mobile smart credentials in the license count. · {1} is the number of licensed mobile smart credentials found in repository.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5082": {
    "name": "Mobile Smart Credential License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials {0} is nearing license limit {1}. Where: · {0} is the current number of licensed mobile smart credentials. · {1} is the mobile smart credential license limit.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5083": {
    "name": "Mobile Smart Credential License At Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed mobile smart credentials has reached the license limit {0}. Where {o} is the mobile smart credential license limit.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5084": {
    "name": "Mobile Smart Credential License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of licensed mobile smart credentials {0} is over license limit {1}. Where: · {0} is the current number of licensed mobile smart credentials. · {1} is the mobile smart credential license limit.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5085": {
    "name": "Mobile Smart Credential License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Mobile Smart Credential license is near expiry date {0}. Where {0} is mobile smart credential license expiry date.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5086": {
    "name": "Mobile Smart Credential License Over Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Mobile Smart Credential license is past expiry date {0}. Where {0} is the mobile smart credential license expiry date.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5087": {
    "name": "Mobile Smart Credential License Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Mobile Smart Credential license was deleted.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5088": {
    "name": "Partition Smart Credential Count Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials in partition {0} reset from {1} to {2}. Where: · {0} is the name of the partition. · {1} is the number of licensed mobile smart credentials in the partition. · {2} is the number of licensed mobile smart credentials assigned to the partition that were found in the repository.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5089": {
    "name": "Partition Smart Credential Count Mismatch",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed smart credentials in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the name of the partition. · {1} is the number of licensed smart credentials in the partition. · {2} is the number of licensed smart credentials assigned to the partition that were found in the repository.",
    "category": "Mobile smart credential license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/mobile_smart_credential_license_audit_messages.htm"
  },
  "AUD5090": {
    "name": "Identity Assured with Smart Credentials License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Identity Assured with Smart Credentials License updated: {0} Where {0} is details about the license update.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5091": {
    "name": "Identity Assured with Smart Credentials License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of Identity Assured with Smart Credentials licenses reset from {0} to {1}. Where: · {0} is the number of Identity Assured with Smart Credentials in the license count. · {1} is the number of licensed smart credentials with identity assured found in repository.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5092": {
    "name": "Identity Assured with Smart Credentials License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of Identity Assured with Smart Credentials licenses {0} is nearing license limit {1}. Where: · {0} is the current number of Identity Assured with Smart Credentials licenses. · {1} is the Identity Assured with Smart Credentials license limit.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5093": {
    "name": "Identity Assured with Smart Credentials License At Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of Identity Assured with Smart Credentials licenses has reached the license limit {0}. Where {o} is the Identity Assured with Smart Credentials license limit.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5094": {
    "name": "Identity Assured with Smart Credentials License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of Identity Assured with Smart Credentials licenses {0} is over license limit {1}. Where: · {0} is the current number of Identity Assured with Smart Credentials licenses. · {1} is the Identity Assured with Smart Credentials license limit.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5095": {
    "name": "Identity Assured with Smart Credentials License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Identity Assured with Smart Credentials license is near expiry date {0}. Where {0} is the Identity Assured with Smart Credentials license expiry date.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5096": {
    "name": "Identity Assured with Smart Credentials License Over Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Identity Assured with Smart Credentials license is past expiry date {0}. Where {0} is the Identity Assured with Smart Credentials license expiry date.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5097": {
    "name": "Identity Assured with Smart Credentials License Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Identity Assured with Smart Credentials license was deleted.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5098": {
    "name": "Partition Identity Assured with Smart Credentials Count Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of Identity Assured with Smart Credentials in partition {0} reset from {1} to {2}. Where: · {0} is the name of the partition. · {1} is the number of Identity Assured with Smart Credentials in the partition. · {2} is the number of Identity Assured with Smart Credentials assigned to the partition that were found in the repository.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5099": {
    "name": "Partition Identity Assured with Smart Credentials Count Mismatch",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of Identity Assured with Smart Credentials in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the name of the partition. · {1} is the number of Identity Assured with Smart Credentials in the partition. · {2} is the number of Identity Assured with Smart Credentials assigned to the partition that were found in the repository.",
    "category": "Identity Assured with Smart Credentials license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/identity_assured_with_smart_credentials_license_audit_messages.htm"
  },
  "AUD5100": {
    "name": "Transaction Verification with Soft Token License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Transaction Verification with Soft Tokens license updated: {0} Where {0} is the expiry date and number of soft tokens licensed for transaction verification allowed.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5101": {
    "name": "Transaction Verification with Soft Token License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of Transaction Verification with Soft Tokens licenses reset from {0} to {1}. Where: · {0} is the number of soft tokens licensed for transaction verification in the Entrust IdentityGuard license count. · {1} is the number of soft tokens licensed for transaction verification found in the repository.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5102": {
    "name": "Transaction Verification with Soft Token License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed transaction verification with soft tokens {0} is nearing license limit {1}. Where: · {0} is the current number of licensed soft tokens with transaction verification. · {1} is the license limit.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5103": {
    "name": "Transaction Verification with Soft Token License At Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed transaction verification with soft tokens {0} has reached the license limit {0}. Where {0} is the current number of licensed soft tokens with transaction verification.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5104": {
    "name": "Transaction Verification with Soft Token License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of licensed transaction verification with soft tokens {0} is over license limit {1}. Where: · {0} is the current number of licensed soft tokens with transaction verification. · {1} is the license limit.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5105": {
    "name": "Transaction Verification with Soft Token License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Transaction Verification with Soft Tokens license is near expiry date {0}. Where {0} is the Transaction Verification with Soft Tokens license expiry date.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5106": {
    "name": "Transaction Verification with Soft Token License Over Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Transaction Verification with Soft Tokens license is past expiry date {0}. Where {0} is the Transaction Verification with Soft Tokens license expiry date.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5107": {
    "name": "Transaction Verification with Soft Token License Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Transaction Verification with Soft Tokens license was deleted.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5108": {
    "name": "Partition Transaction Verification with Soft Token Count Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed soft tokens with transaction verification in partition {0} reset from {1} to {2}. Where: · {0} is the name of the partition. · {1} is the number of licensed soft tokens with transaction verification in the partition. · {2} is the number of licensed soft tokens with transaction verification assigned to the partition that were found in the repository.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5109": {
    "name": "Partition Transaction Verification with Soft Token Count Mismatch",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed soft tokens with transaction verification in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the name of the partition. · {1} is the number of licensed soft tokens with transaction verification in the partition. · {2} is the number of licensed soft tokens with transaction verification assigned to the partition that were found in the repository.",
    "category": "Transaction Verification with Soft Tokens license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/transaction_verification_with_soft_tokens_license_audit_messages.htm"
  },
  "AUD5110": {
    "name": "Biometrics License Updated",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Biometrics license updated: {0} Where {0} is the expiry date and number of biometrics allowed.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5111": {
    "name": "Biometrics License Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed biometrics reset from {0} to {1}. Where: · {0} is the number of biometrics in the Entrust IdentityGuard license count. · {1} is the number of licensed biometrics found in the repository.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5112": {
    "name": "Biometrics License Near Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed biometrics {0} is nearing license limit {1}. Where: · {0} is the current number of licensed biometrics. · {1} is the license limit.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5113": {
    "name": "Biometrics License At Limit",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed biometrics has reached the license limit {0}. Where {0} is the current number of licensed biometrics.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5114": {
    "name": "Biometrics License Over Limit",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Number of licensed biometrics {0} is over license limit {1}. Where: · {0} is the current number of licensed biometrics. · {1} is the license limit.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5115": {
    "name": "Biometrics License Near Expiry",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Biometrics license is near expiry date {0}. Where {0} is the Biometrics license expiry date.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5116": {
    "name": "Biometrics License Over Expiry",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "Biometrics license is past expiry date {0}. Where {0} is the Biometrics license expiry date.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5117": {
    "name": "Biometrics License Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Biometrics license was deleted.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5118": {
    "name": "Partition Biometrics Count Reset",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "Number of licensed biometrics in partition {0} reset from {1} to {2}. Where: · {0} is the name of the partition. · {1} is the number of licensed biometrics in the partition. · {2} is the number of licensed biometrics assigned to the partition that were found in the repository.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5119": {
    "name": "Partition Biometrics Count MisMatch",
    "level": "WARN",
    "snmp": "Yes",
    "desc": "Number of licensed biometrics in partition {0} ({1}) does not match the count from the repository ({2}). Where: · {0} is the name of the partition. · {1} is the number of licensed biometrics in the partition. · {2} is the number of licensed biometrics assigned to the partition that were found in the repository.",
    "category": "Biometrics license audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/biometrics_license_audit_messages.htm"
  },
  "AUD5200": {
    "name": "Audits Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "{0} audits deleted. {1} Where: · {0} is the number of audits that were deleted. · {1} is the range of audit sequence numbers that were deleted.",
    "category": "Audit based audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/audit_based_audit_messages.htm"
  },
  "AUD5201": {
    "name": "Audits Cleaned",
    "level": "INFO",
    "snmp": "",
    "desc": "{0} audits generated before {1} were deleted. {2} Where: · {0} is the number of audits that were deleted. · {1} is the latest audit date for which audits were deleted. · {2} is an optional string indicating where audits were exported.",
    "category": "Audit based audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/audit_based_audit_messages.htm"
  },
  "AUD5202": {
    "name": "Audit Cleaner Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The audit database cleaner task failed.",
    "category": "Audit based audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/audit_based_audit_messages.htm"
  },
  "AUD5300": {
    "name": "Audit External",
    "level": "INFO",
    "snmp": "",
    "desc": "{0} Where {0} is the audit text provided by the external service.",
    "category": "Audit based audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/audit_based_audit_messages.htm"
  },
  "AUD5400": {
    "name": "Smart Credential Definition Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Definition {0} created: {1} Where: · {0} is the Smart Credential Definition name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential definition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_definition_audit_messages.htm"
  },
  "AUD5401": {
    "name": "Smart Credential Definition Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Definition {0} updated: {1} Where: · {0} is the Smart Credential Definition name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential definition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_definition_audit_messages.htm"
  },
  "AUD5402": {
    "name": "Smart Credential Definition Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Definition {0} deleted. Where {0} is the Smart Credential Definition name.",
    "category": "Smart credential definition audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_definition_audit_messages.htm"
  },
  "AUD5410": {
    "name": "Smart Credential Print Module Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Print Module {0} created: {1} Where: · {0} is the print module name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential print module audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_print_module_audit_messages.htm"
  },
  "AUD5411": {
    "name": "Smart Credential Print Module Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Print Module {0} updated: {1} Where: · {0} is the print module name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential print module audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_print_module_audit_messages.htm"
  },
  "AUD5412": {
    "name": "Smart Credential Print Module Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Print Module {0} deleted. Where {0} is the print module name.",
    "category": "Smart credential print module audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_print_module_audit_messages.htm"
  },
  "AUD5413": {
    "name": "Smart Credential Print Module Wipe",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Print Module {0} wipe. Where {0} is the print module name.",
    "category": "Smart credential print module audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_print_module_audit_messages.htm"
  },
  "AUD5420": {
    "name": "Smart Credential Applet Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Applet {0} created: {1} Where: · {0} is the Smart Credential applet name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential applet audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_applet_audit_messages.htm"
  },
  "AUD5421": {
    "name": "Smart Credential Applet Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Applet {0} updated: {1} Where: · {0} is the Smart Credential applet name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential applet audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_applet_audit_messages.htm"
  },
  "AUD5422": {
    "name": "Smart Credential Applet Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Applet {0} deleted. Where {0} is the Smart Credential applet name.",
    "category": "Smart credential applet audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_applet_audit_messages.htm"
  },
  "AUD5430": {
    "name": "Smart Credential Graphic Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Graphic {0} created: {1} Where: · {0} is the Smart Credential graphic name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential graphic audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_graphic_audit_messages.htm"
  },
  "AUD5431": {
    "name": "Smart Credential Graphic Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Graphic {0} updated: {1} Where: · {0} is the Smart Credential graphic name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential graphic audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_graphic_audit_messages.htm"
  },
  "AUD5432": {
    "name": "Smart Credential Graphic Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Graphic {0} deleted. Where {0} is the Smart Credential graphic name.",
    "category": "Smart credential graphic audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_graphic_audit_messages.htm"
  },
  "AUD5440": {
    "name": "Smart Credential Layout Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Layout {0} created: {1} Where: · {0} is the Smart Credential layout name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential layout audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_layout_audit_messages.htm"
  },
  "AUD5441": {
    "name": "Smart Credential Layout Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Layout {0} updated: {1} Where: · {0} is the Smart Credential layout name. · {1} is a list of settings updated and their new values.",
    "category": "Smart credential layout audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_layout_audit_messages.htm"
  },
  "AUD5442": {
    "name": "Smart Credential Layout Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Smart Credential Layout {0} deleted. Where {0} is the Smart Credential layout name.",
    "category": "Smart credential layout audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/smart_credential_layout_audit_messages.htm"
  },
  "AUD5450": {
    "name": "Managed CA Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Managed CA {0} created: {1} Where: · {0} is the name of the managed CA. · {1} is a list of details about the managed CA.",
    "category": "Managed CA audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/managed_ca_audit_messages.htm"
  },
  "AUD5451": {
    "name": "Managed CA Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Managed CA {0} updated: {1} Where: · {0} is the name of the managed CA. · {1} is a list of details about the managed CA.",
    "category": "Managed CA audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/managed_ca_audit_messages.htm"
  },
  "AUD5452": {
    "name": "Managed CA Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Managed CA {0} deleted. Where {0} is the name of the managed CA.",
    "category": "Managed CA audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/managed_ca_audit_messages.htm"
  },
  "AUD5453": {
    "name": "Managed CA Management Occurred",
    "level": "INFO",
    "snmp": "",
    "desc": "The Managed CA management task updated the {0} digital identity for the {1} managed CA. Where: · {0} is the name of the digital identity that was updated. · {1} is the name of the managed CA.",
    "category": "Managed CA audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/managed_ca_audit_messages.htm"
  },
  "AUD5454": {
    "name": "Managed CA Management Failed",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The Managed CA management task failed.",
    "category": "Managed CA audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/managed_ca_audit_messages.htm"
  },
  "AUD5455": {
    "name": "Managed CA Management Failure",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The Managed CA management task failed while attempting to update the {0} digital identity for the {1} managed CA. Where: · {0} is the name of the digital identity for which the update was attempted. · {1} is the name of the managed CA.",
    "category": "Managed CA audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/managed_ca_audit_messages.htm"
  },
  "AUD5460": {
    "name": "Digital ID Configuration Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id Config {0} created: {1} Where: · {0} is the name of the digital ID configuration. · {1} is a list of settings updated and their new values.",
    "category": "Digital ID configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/digital_id_configuration_audit_messages.htm"
  },
  "AUD5461": {
    "name": "Digital ID Configuration Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id Config {0} updated: {1} Where: · {0} is the name of the digital ID configuration. · {1} is a list of settings updated and their new values.",
    "category": "Digital ID configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/digital_id_configuration_audit_messages.htm"
  },
  "AUD5462": {
    "name": "Digital ID Configuration Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Digital Id Config {0} deleted. Where {0} is the name of the digital ID configuration.",
    "category": "Digital ID configuration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/digital_id_configuration_audit_messages.htm"
  },
  "AUD5470": {
    "name": "PACS Created",
    "level": "INFO",
    "snmp": "",
    "desc": "PACS {0} created: {1} Where: · {0} is the PACS name. · {1} is a list of settings updated and their new values.",
    "category": "PACS audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/pacs_audit_messages.htm"
  },
  "AUD5471": {
    "name": "PACS Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "PACS {0} updated: {1} Where: · {0} is the PACS name. · {1} is a list of settings updated and their new values.",
    "category": "PACS audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/pacs_audit_messages.htm"
  },
  "AUD5472": {
    "name": "PACS Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "PACS {0} deleted. Where {0} is the PACS name.",
    "category": "PACS audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/pacs_audit_messages.htm"
  },
  "AUD5480": {
    "name": "Proxy Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Proxy {0} created: {1} Where: · {0} is the Proxy name. · {1} is a list of settings updated and their new values.",
    "category": "Proxy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/proxy_audit_messages.htm"
  },
  "AUD5481": {
    "name": "Proxy Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Proxy {0} updated: {1} Where: · {0} is the Proxy name. · {1} is a list of settings updated and their new values.",
    "category": "Proxy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/proxy_audit_messages.htm"
  },
  "AUD5482": {
    "name": "Proxy Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Proxy {0} deleted. Where {0} is the Proxy name.",
    "category": "Proxy audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/proxy_audit_messages.htm"
  },
  "AUD6000": {
    "name": "Authentication Success",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} successfully authenticated a challenge. {1} Where: · {0} is the user ID. · {1} is a list of parameters including the authentication type, and possibly the location and application name. Note: By default, this audit is disabled. To add this message to logs, set the Audit Successful Authentications property to True.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6001": {
    "name": "Authentication Failure",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} failed authentication. {1} Where: · {0} is the user ID. · {1} is a list of parameters including the authentication type, and possibly the location and application name.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6002": {
    "name": "Authentication Failure Locks Out User",
    "level": "ERROR",
    "snmp": "",
    "desc": "User {0} failed authentication and is now locked{1,choice,0#|1# out of {2} authentication}. Where: · {0} is the user ID.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6003": {
    "name": "Shared Secrets Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Shared secrets for user {0} updated. Where {0} is the user ID.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6004": {
    "name": "Authentication Causes Card Update",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} authenticated with pending card. Card {1} updated. {2} Where: · {0} is the user ID. · {1} is the serial number of the card. · {2} is a list of parameters, including the new state of the card.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6005": {
    "name": "Card Replacement Warning",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} authenticated with a card ({1}) that is in the replacement warning period. Where: · {0} is the user ID. · {1} is the serial number of the card.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6006": {
    "name": "Card Replacement Required",
    "level": "WARN",
    "snmp": "",
    "desc": "User {0} authenticated with a card ({1}) that is in the replacement required period. Card has been placed on hold. Where: · {0} is the user ID. · {1} is the serial number of the card.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6007": {
    "name": "Authentication Causes Machine Registration",
    "level": "INFO",
    "snmp": "",
    "desc": "New machine registered for user {0}. Where {0} is the user ID.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6008": {
    "name": "Authentication Causes Shared Secrets Update",
    "level": "INFO",
    "snmp": "",
    "desc": "Authentication secrets for user {0} updated. Where {0} is the user ID.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6009": {
    "name": "Authentication Causes Token Update",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} authenticated with pending token. Token {1} updated. {2} Where: · {0} is the user ID. · {1} is the vendor/serial number of token. · {2} is list of parameters including new state of the token.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6010": {
    "name": "Authentication Attempt By Suspended User",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted an Authentication API {1} operation while suspended. Where: · {0} is the user ID. · {1} is the API operation being performed.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6011": {
    "name": "Challenge Request Results in Rejection",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} challenge request was rejected. {1} Where: · {0} is the user ID. · {1} is a list of parameters, including the result of IP and machine authentication, security level of the request, and possibly the location of the user.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6012": {
    "name": "Challenge Request Results in Challenge",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} challenge request was challenged. {1} Where: · {0} is the user ID. · {1} is a list of parameters, including the result of IP and machine authentication, security level of the request, and possibly the location of the user. Note: By default, this audit is disabled. To add this message to logs, set the Audit Challenge Requests That Return Challenge property to True.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6013": {
    "name": "Challenge Request Results in Authentication",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} challenge request was authenticated. {1} Where: · {0} is the user ID. · {1} is a list of parameters, including the result of IP and machine authentication, security level of the request, and possibly the location of the user. Note: By default, this audit is disabled. To add this message to logs, set the Audit Challenge Requests That Return Authenticated property to True.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6014": {
    "name": "Incorrectly Answered Questions in Challenge Response",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} answered the following questions incorrectly: {1} Where: · {0} is the user ID. · {1} is a list of questions that the user answered incorrectly. Note: By default, this audit is disabled. To add this message to logs, set the Audit Knowledge-Based Questions That Are Answered Incorrectly property to True.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6015": {
    "name": "Machine Registration Check Success",
    "level": "INFO",
    "snmp": "",
    "desc": "Machine registration check for user {0} succeeded. Where {0} is the user ID. Note: This audit property applies only to machine authentication performed via the Entrust IdentityGuard 9.0 V1 or V2 API.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6016": {
    "name": "Machine Registration Check Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Machine registration check for user {0} failed. Where {0} is the user ID. Note: This audit property applies only to machine authentication performed via the Entrust IdentityGuard 9.0 V1 or V2 API.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6017": {
    "name": "Transaction Receipt Signing Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Failed generating transaction receipt signature.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6018": {
    "name": "Authentication Attempt With Disabled Directory Account",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted an Authentication API {1} operation when their directory account was disabled. Where: · {0} is the user ID. · {1} is the API operation being performed.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6019": {
    "name": "Authentication Attempt With Expired Directory Account",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted an Authentication API {1} operation when their directory account was expired. Where: · {0} is the user ID. · {1} is the API operation being performed.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6020": {
    "name": "User Token Requires Reset",
    "level": "ERROR",
    "snmp": "",
    "desc": "Token {1} {2} for user {0} requires a reset. Where: · {0} is the user ID. · {1} is the token vendor. · {2} is the token serial number.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6021": {
    "name": "No Second Factor Authentication Types Available",
    "level": "ERROR",
    "snmp": "",
    "desc": "User {0} was challenged but has no second-factor authenticators available. Where {0} is the user ID.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6022": {
    "name": "Authentication User Not Exist",
    "level": "ERROR",
    "snmp": "",
    "desc": "User {0} does not exist. Where {0} is the user ID.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6023": {
    "name": "Certificate Transaction Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Certificate transaction failed with status {1} for user {0}. Where: · {0} is the user ID. · {1} is the transaction status.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6024": {
    "name": "Token Transaction Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "Token transaction failed with status {1} for user {0}. Where: · {0} is the user ID. · {1} is the transaction status.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6025": {
    "name": "Authentication Request Rejected",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} authentication request was rejected. {1} Where: · {0} is the user ID. · {1} is the list of parameters.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6026": {
    "name": "Authentication Attempt With Orphaned User",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} attempted an Authentication API {1} operation when their directory account was orphaned. Where: · {0} is the user ID. · {1} is the operation.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6028": {
    "name": "Invalid Combined Challenge Returned",
    "level": "INFO",
    "snmp": "",
    "desc": "The combined challenge request for user {0} resulted in one or more invalid challenges being returned. {1} · {0} is the userid · {1} is a list of parameters including the authentication types that were successfully validated and possibly the application name.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6029": {
    "name": "Combined Authentication Success",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} successfully authenticated a combined challenge. {1} · {0} is the userid · {1} is a list of parameters including the authentication type that caused the failure as well as the failure cause and possibly the application name.",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD6030": {
    "name": "Combined Authentication Failure",
    "level": "ERROR",
    "snmp": "",
    "desc": "User {0} failed combined authentication. {1} · {0} is the property name · {1} is a Boolean flag indicating whether a property is sensitive · {2} is the property value displayed for non-sensitive properties",
    "category": "Authentication audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/authentication_audit_messages.htm"
  },
  "AUD7000": {
    "name": "Property Created",
    "level": "INFO",
    "snmp": "",
    "desc": "Property {0} was added with a value of {1,choice,0#[Sensitive Data]|1#”{2}”} Where: · {0} is the property name. · {1} is the boolean flag indicating whether or not the property is sensitive. · {2} is the property value displayed for non-sensitive properties.",
    "category": "Property editor audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_editor_audit_messages.htm"
  },
  "AUD7001": {
    "name": "Property Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Property {0} had its value changed from {1,choice,0#[Sensitive Data]|1#”{2}”} to {1,choice,0#[Sensitive Data]|1#”{3}”}. Where: · {0} is the property name. · {1} is the boolean flag indicating whether or not the property is sensitive. · {2} is the old property value displayed for non-sensitive properties. · {3} is the new property value displayed for non-sensitive properties.",
    "category": "Property editor audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_editor_audit_messages.htm"
  },
  "AUD7002": {
    "name": "Property Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Property {0} was deleted. Where {0} is the property name.",
    "category": "Property editor audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_editor_audit_messages.htm"
  },
  "AUD7003": {
    "name": "Property Encrypted",
    "level": "INFO",
    "snmp": "",
    "desc": "Property {0} was changed from unencrypted to encrypted. Where {0} is the property name.",
    "category": "Property editor audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_editor_audit_messages.htm"
  },
  "AUD7004": {
    "name": "Property Decrypted",
    "level": "INFO",
    "snmp": "",
    "desc": "Property {0} was changed from encrypted to unencrypted. Where {0} is the property name.",
    "category": "Property editor audit messages",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/property_editor_audit_messages.htm"
  },
  "AUD7500": {
    "name": "Invalid Radius Message Received",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The Entrust IdentityGuard Radius Proxy received an invalid Radius message from {0}. Where {0} is the address of the client that sent the bad message.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7501": {
    "name": "Radius Server Address Has Changed",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The Entrust IdentityGuard Radius Proxy has switched the address for Radius server {0} to {1}. Where: · {0} is the name of the Radius server. · {1} is the new address.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7502": {
    "name": "Too Many Outstanding Requests For Radius Proxy",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The Entrust IdentityGuard Radius Proxy has too many outstanding requests.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7503": {
    "name": "No Response From Radius Server",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "The Entrust IdentityGuard Radius Proxy timed out waiting for a response from a Radius server {0} for an authentication request for user {1}. Where: · {0} is the name of the Radius server. · {1} is the user performing authentication.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7504": {
    "name": "Radius Proxy Skipped Second Factor Authentication",
    "level": "INFO",
    "snmp": "",
    "desc": "User {0} skipped second-factor authentication in Entrust Radius Proxy because the user does not exist or does not have active credentials. Where {1} is the user performing authentication.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7505": {
    "name": "Radius Server Rejected Authentication",
    "level": "INFO",
    "snmp": "",
    "desc": "The Radius server {0} rejected authentication for user {1}. Where: · {0} is the name of the Radius server. · {1} is the user performing authentication.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7506": {
    "name": "Radius Server Accepted Authentication",
    "level": "INFO",
    "snmp": "",
    "desc": "The Radius server {0} accepted authentication for user {1}. Where: · {0} is the name of the Radius server. · {1} is the user performing authentication.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7507": {
    "name": "Authentication Forwarded to Displaced Server",
    "level": "INFO",
    "snmp": "",
    "desc": "Authentication for user {1} has been forwarded to the displaced server {0}. Where: · {0} is the name of the displaced Radius server. · {1} is the user performing authentication.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD7510": {
    "name": "Invalid Radius Configuration",
    "level": "ERROR",
    "snmp": "",
    "desc": "Entrust IdentityGuard Radius has invalid configuration.",
    "category": "Entrust IdentityGuard Radius proxy audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/entrust_identityguard_radius_proxy_audits.htm"
  },
  "AUD8000": {
    "name": "User Certificate Assigned",
    "level": "INFO",
    "snmp": "",
    "desc": "Certificate {1} {2} has been assigned to user {0}. {3} Where: · {0} is the user ID of user. · {1} is the certificate issuer DN. · {2} is the certificate serial number. · {3} is the certificate details.",
    "category": "User certificate audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_certificate_audits.htm"
  },
  "AUD8001": {
    "name": "User Certificate Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "Certificate {1} {2} for user {0} has been deleted. Where: · {0} is the user ID of user. · {1} is the certificate issuer DN. · {2} is the certificate serial number.",
    "category": "User certificate audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_certificate_audits.htm"
  },
  "AUD8002": {
    "name": "User Certificate Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "Certificate {1} {2} for user {0} has been updated. {3} Where: · {0} is the user ID of user. · {1} is the certificate issuer DN. · {2} is the certificate serial number. · {3} is the certificate details.",
    "category": "User certificate audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/user_certificate_audits.htm"
  },
  "AUD8010": {
    "name": "CA Certificate Loaded",
    "level": "INFO",
    "snmp": "",
    "desc": "CA Certificate {0} has been loaded. {1} Where: · {0} is the name of the CA certificate. · {1} is the certificate details.",
    "category": "CA certificate audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/ca_certificate_audits.htm"
  },
  "AUD8011": {
    "name": "CA Certificate Deleted",
    "level": "INFO",
    "snmp": "",
    "desc": "CA Certificate {0} has been deleted. Where {0} is the name of the CA certificate.",
    "category": "CA certificate audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/ca_certificate_audits.htm"
  },
  "AUD8012": {
    "name": "CA Certificate Updated",
    "level": "INFO",
    "snmp": "",
    "desc": "CA Certificate {0} has been updated. {1} Where: · {0} is the name of the CA certificate. · {1} is the certificate details.",
    "category": "CA certificate audits",
    "manualFile": "IG_130_Admin_WebHelp/ig_admin/config_logging/ca_certificate_audits.htm"
  },
  "AUD8300": {
    "name": "Device paired with account",
    "level": "INFO",
    "snmp": "",
    "desc": "Paired device id {0} with Entrust IdentityGuard user account {1}, using external user id {2}, for Risk Engine {3}. {4} Where: {0} - device id {1} - userid {2} - external user id (hashed) {3} - external risk provider {4} - details about the device Example: Paired device id 0123456789 with Entrust IdentityGuard user account default/jdoe, using external user id ADFA3241254FDF0, for Risk Engine iovation. OS: Windows, Browser: TRIDENT",
    "category": "Risk engine audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/risk_engine_audit_messages.htm"
  },
  "AUD8301": {
    "name": "One device unpaired from account",
    "level": "INFO",
    "snmp": "",
    "desc": "Unpaired device id {0} associated with Entrust IdentityGuard user account {1}, using external user id {2}, for Risk Engine {3}. Where: {0} - device id {1} - userid {2} - external user id (hashed) {3} - external risk provider Example: Unpaired device id 0123456789 associated with Entrust IdentityGuard user account default/jdoe, using external user id ADFA3241254FDF0, for Risk Engine iovation.",
    "category": "Risk engine audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/risk_engine_audit_messages.htm"
  },
  "AUD8302": {
    "name": "All devices unpaired from account",
    "level": "INFO",
    "snmp": "",
    "desc": "Unpaired {0} device(s) associated with Entrust IdentityGuard user account {1}, using external user id {2}, for Risk Engine {3}. Where {0} - number of devices unpaired {1} - userid {2} - external user id (hashed) {3} - external risk provider Example: Unpaired 3 device(s) associated with Entrust IdentityGuard user account default/jdoe, using external user id ADFA3241254FDF0, for Risk Engine iovation.",
    "category": "Risk engine audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/risk_engine_audit_messages.htm"
  },
  "AUD8303": {
    "name": "Authentication failure reported to risk engine",
    "level": "ERROR",
    "snmp": "",
    "desc": "Failed authentication using Risk Engine {0} for Entrust IdentityGuard user account {1}, using external user id {2}, for device id {3}. Where: {0} - external risk provider {1} - userid {2} - external user id (hashed) {3} - device id Example: Failed authentication using Risk Engine iovation for Entrust IdentityGuard user account default/jdoe, using external user id ADFA3241254FDF0, for device id 0123456789.",
    "category": "Risk engine audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/risk_engine_audit_messages.htm"
  },
  "AUD8304": {
    "name": "External Risk Engine explicit deny reason",
    "level": "ERROR",
    "snmp": "",
    "desc": "Risk Engine {0} rejected device id {1} with reason: {2}. Where: {0} - external risk provider {2} - device id {3} - reason Example: Risk Engine iovation rejected device id 0123456789 with reason: invalid admin username or password.",
    "category": "Risk engine audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/risk_engine_audit_messages.htm"
  },
  "AUD8500": {
    "name": "IntelliTrust Migration Export Start",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "IntelliTrust Migration authenticator export started",
    "category": "IntelliTrust migration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/intellitrust_migration_audit_messages.htm"
  },
  "AUD8501": {
    "name": "IntelliTrust Migration Export Failed",
    "level": "ERROR",
    "snmp": "Yes",
    "desc": "IntelliTrust Migration authenticator export failed",
    "category": "IntelliTrust migration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/intellitrust_migration_audit_messages.htm"
  },
  "AUD8502": {
    "name": "IntelliTrust Migration Export Finished",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "IntelliTrust Migration authenticator export completed with status {0}. Where: · {0} is a string with information about the export. Example: authexport: Export file: C:\\Program Files\\Entrust\\IdentityGuard\\identityguard120\\testexport9.dat, steps completed: 2 of 2, user number: 156 of maximum user number: 156, exported users: 79 of possible 156, exported unassigned tokens: 28, Done at: Fri Oct 20 07:38:33 GMT-04:00 2017",
    "category": "IntelliTrust migration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/intellitrust_migration_audit_messages.htm"
  },
  "AUD8503": {
    "name": "IntelliTrust Migration Export Password View",
    "level": "INFO",
    "snmp": "Yes",
    "desc": "IntelliTrust Migration authenticator export password was displayed to a master user",
    "category": "IntelliTrust migration audit messages",
    "manualFile": "IG_130_Admin_WebHelp/igreferencesection/intellitrust_migration_audit_messages.htm"
  }
};
