/**
 * KB-DATABASE: Base de Conocimientos de Diagnóstico de Logs, Auditoría y Trazas
 * Soporta Entrust IdentityGuard OnPremise (Errores 520xxx y Auditoría AUDxxx)
 * e IDaaS Cloud.
 */

class KnowledgeBase {
  constructor() {
    this.storageKey = 'kb_custom_rules_v1';
    this.defaultRules = [
      // ==========================================
      // AUDITORÍA DE SERVICIOS Y ALTA DISPONIBILIDAD (AUD106 - AUD155)
      // ==========================================
      {
        id: 'KB-ENTRUST-AUD106',
        title: 'Entrust Audit: Service Start (Inicio de Servicio)',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'INFO',
        pattern: /(AUD106|service started)/i,
        meaning: 'El servicio {0} de Entrust IdentityGuard inició correctamente.',
        rootCause: 'Arranque regular del servicio de administración o autenticación.',
        remediation: 'No requiere acción. Registrado con trampa SNMP por defecto.',
        riskLevel: 'Bajo (Inicio de Servicio)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud106',
        sectionTitle: 'Código [AUD106]: Service Start'
      },
      {
        id: 'KB-ENTRUST-AUD107',
        title: 'Entrust Audit: Service Stop (Detención de Servicio)',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'INFO',
        pattern: /(AUD107|service stopped)/i,
        meaning: 'El servicio {0} de Entrust IdentityGuard fue detenido.',
        rootCause: 'Detención manual o reinicio programado del servicio por el administrador.',
        remediation: 'Verifique si la detención fue planificada.',
        riskLevel: 'Medio (Detención de Servicio)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud107',
        sectionTitle: 'Código [AUD107]: Service Stop'
      },
      {
        id: 'KB-ENTRUST-AUD125',
        title: 'Entrust Audit: Fallo Conexión Property Editor a Servicio Administración',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'ERROR',
        pattern: /(AUD125|Properties Editor failed to connect to the.*Administration Service)/i,
        meaning: 'El Editor de Propiedades no pudo conectar con el Servicio de Administración de Entrust IdentityGuard.',
        rootCause: 'Servicio de Administración detenido, firewall bloqueando puerto o TLS inválido.',
        remediation: '1. Verifique el estado del Servicio de Administración.\n2. Compruebe la conectividad de red y certificados.',
        riskLevel: 'Alto (Fallo de Conexión Editor / SNMP Trap Activado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud125',
        sectionTitle: 'Código [AUD125]: Property Editor Connection Failure'
      },
      {
        id: 'KB-ENTRUST-AUD126',
        title: 'Entrust Audit: Fallo Conexión Interfaz Administración a Servicio Administración',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'ERROR',
        pattern: /(AUD126|Administration interface failed to connect to the.*Administration Service)/i,
        meaning: 'La consola/interfaz de administración no pudo conectarse con el Servicio de Administración.',
        rootCause: 'Servicio de administración no disponible o tiempo de espera (timeout) excedido.',
        remediation: 'Reinicie el Servicio de Administración y compruebe los logs de arranque (AUD110).',
        riskLevel: 'Alto (Consola Administrativa Inaccesible)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud126',
        sectionTitle: 'Código [AUD126]: Administration Interface Connection Failure'
      },
      {
        id: 'KB-ENTRUST-AUD127',
        title: 'Entrust Audit: Fallo Conexión RADIUS Proxy a Servicio Autenticación',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'ERROR',
        pattern: /(AUD127|Radius Proxy failed to connect to the.*Authentication service)/i,
        meaning: 'El Proxy RADIUS no puede comunicarse con el Servicio de Autenticación de Entrust.',
        rootCause: 'Servicio de Autenticación caído o puerto interno bloqueado.',
        remediation: '1. Verifique que el servicio `identityguard-auth` esté activo.\n2. Revise las reglas del firewall local.',
        riskLevel: 'Crítico (Bloqueo de Autenticación RADIUS / VPN)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud127',
        sectionTitle: 'Código [AUD127]: Radius Proxy Connection Failure'
      },
      {
        id: 'KB-ENTRUST-AUD150',
        title: 'Entrust Audit: Fallo Conexión Proxy Repositorio a Servicio Autenticación',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'ERROR',
        pattern: /(AUD150|Failed to connect to repository.*with URL)/i,
        meaning: 'Fallo al conectar con el repositorio de datos (Base de datos o LDAP) en la URL especificada.',
        rootCause: 'Base de datos/LDAP inalcanzable, credenciales de conexión expiradas o falla de red.',
        remediation: '1. Verifique el estado de la base de datos SQL / directorio LDAP.\n2. Pruebe la conectividad mediante `ping` / `telnet`.',
        riskLevel: 'Alto (Repositorio Inalcanzable)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud150',
        sectionTitle: 'Código [AUD150]: Repository Proxy Connection Failure'
      },
      {
        id: 'KB-ENTRUST-AUD151',
        title: 'Entrust Audit: Alta Disponibilidad - Conmutación por Error de Repositorio (Failover HA)',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'WARN',
        pattern: /(AUD151|Repository.*connection failed to URL.*switching to URL)/i,
        meaning: 'Se produjo un evento de Conmutación por Error (Failover) en Alta Disponibilidad. La conexión al repositorio primario falló y se cambió automáticamente a la URL secundaria.',
        rootCause: 'Caída del servidor de base de datos primario o corte temporal de enlace de red.',
        remediation: '1. Investigue por qué falló la URL principal.\n2. Restablezca el nodo primario para permitir la conmutación de regreso (AUD152).',
        riskLevel: 'Medio (Failover de Base de Datos Activado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud151',
        sectionTitle: 'Código [AUD151]: High Availability Repository Failover'
      },
      {
        id: 'KB-ENTRUST-AUD152',
        title: 'Entrust Audit: Alta Disponibilidad - Repositorio Primario Restablecido',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'INFO',
        pattern: /(AUD152|primary connection has been restored for repository)/i,
        meaning: 'Se restableció la conexión con el servidor de repositorio primario en el esquema de Alta Disponibilidad.',
        rootCause: 'Recuperación del nodo primario de base de datos o LDAP.',
        remediation: 'No requiere acción. Operación normal restaurada.',
        riskLevel: 'Bajo (HA Primario Restaurado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud152',
        sectionTitle: 'Código [AUD152]: High Availability Primary Repository Restored'
      },
      {
        id: 'KB-ENTRUST-AUD153',
        title: 'Entrust Audit: Fallo Total de Conexión en Alta Disponibilidad (HA Failure)',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'CRITICAL',
        pattern: /(AUD153|Failed to establish a connection to any supplied URLs for repository)/i,
        meaning: 'Fallo total de conectividad en Alta Disponibilidad. No se pudo establecer conexión con NINGUNA de las URLs de repositorio configuradas (Primaria y Réplicas cayeron).',
        rootCause: 'Caída general de la infraestructura de base de datos o fallo completo de red.',
        remediation: '1. Inicie inmediatamente la recuperación del clúster de base de datos SQL/LDAP.\n2. Verifique la infraestructura de red.',
        riskLevel: 'Crítico (Caída Total de Repositorios)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud153',
        sectionTitle: 'Código [AUD153]: High Availability Connection Failure'
      },
      {
        id: 'KB-ENTRUST-AUD154',
        title: 'Entrust Audit: Agotamiento del Pool de Conexiones a Repositorio',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'WARN',
        pattern: /(AUD154|Failed to obtain a connection to repository.*from the connection pool due to pool exhaustion)/i,
        meaning: 'Se agotó por completo el pool de conexiones de base de datos (Connection Pool Exhausted). Las solicitudes entrantes están bloqueadas esperando conexión.',
        rootCause: 'Alta carga de peticiones simultáneas de autenticación o límite de conexiones máximas en `identityguard.properties` demasiado bajo.',
        remediation: '1. Incremente el número máximo de conexiones en el pool de repositorios.\n2. Verifique si hay consultas colgadas en la base de datos SQL.',
        riskLevel: 'Alto (Pool de Conexiones Agotado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud154',
        sectionTitle: 'Código [AUD154]: Connection Pool Exhausted'
      },
      {
        id: 'KB-ENTRUST-AUD155',
        title: 'Entrust Audit: Pool de Conexiones al 80% de Capacidad',
        category: 'Entrust OnPremise / Servicios & HA',
        severity: 'WARN',
        pattern: /(AUD155|Connection pool to repository.*is 80 percent used)/i,
        meaning: 'El pool de conexiones al repositorio ha alcanzado el 80% de su capacidad máxima.',
        rootCause: 'Incremento sostenido en la demanda de autenticaciones o usuarios concurrentes.',
        remediation: 'Monitoree el uso de conexiones y evalúe ampliar el tamaño del pool antes de llegar al 100%.',
        riskLevel: 'Medio (Alerta Preventiva de Capacidad)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud155',
        sectionTitle: 'Código [AUD155]: Connection Pool 80 Percent Used'
      },

      // ==========================================
      // AUDITORÍA DE CONFIGURACIÓN DE PROPIEDADES (AUD121 - AUD148)
      // ==========================================
      {
        id: 'KB-ENTRUST-AUD121',
        title: 'Entrust Audit: Error de Sintaxis en Archivo de Propiedades (Invalid Property Config)',
        category: 'Entrust OnPremise / Configuración de Propiedades',
        severity: 'ERROR',
        pattern: /(AUD121|error was detected parsing a property in the properties file)/i,
        meaning: 'Error al analizar sintácticamente una propiedad dentro del archivo `identityguard.properties`.',
        rootCause: 'Sintaxis inválida, caracter especial no permitido o propiedad mal formateada.',
        remediation: '1. Abra el archivo de propiedades indicado en el log.\n2. Corrija el valor o restaure la línea configurada.',
        riskLevel: 'Alto (Error de Configuración / Trampa SNMP Activada)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud121',
        sectionTitle: 'Código [AUD121]: Invalid Property Configuration'
      },
      {
        id: 'KB-ENTRUST-AUD128',
        title: 'Entrust Audit: Error de Configuración de Servidor SMTP',
        category: 'Entrust OnPremise / Configuración de Propiedades',
        severity: 'ERROR',
        pattern: /(AUD128|Errors were detected in the SMTP server properties)/i,
        meaning: 'Se detectaron errores en las propiedades de configuración del servidor de correo SMTP.',
        rootCause: 'Host SMTP incorrecto, puerto inválido, credenciales o TLS mal configurado.',
        remediation: '1. Abra el Editor de Propiedades de IdentityGuard.\n2. Ingrese a Configuración SMTP y pruebe el envío de correo de prueba.',
        riskLevel: 'Alto (Fallo de Correo / Notificaciones)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud128',
        sectionTitle: 'Código [AUD128]: Invalid SMTP Configuration'
      },
      {
        id: 'KB-ENTRUST-AUD135',
        title: 'Entrust Audit: Error de Configuración de Servidor SMS',
        category: 'Entrust OnPremise / Configuración de Propiedades',
        severity: 'ERROR',
        pattern: /(AUD135|Errors were detected in the SMS server properties)/i,
        meaning: 'Errores en las propiedades de configuración del Gateway de SMS.',
        rootCause: 'URL de API SMS gateway inválida, token de API caducado o parámetros HTTP incorrectos.',
        remediation: 'Verifique la integración con el proveedor de SMS en la consola de administración.',
        riskLevel: 'Alto (Fallo de Despacho OTP por SMS)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud135',
        sectionTitle: 'Código [AUD135]: Invalid SMS Configuration'
      },

      // ==========================================
      // AUDITORÍA DE PLANTILLAS SMART CREDENTIALS (AUD137 - AUD139)
      // ==========================================
      {
        id: 'KB-ENTRUST-AUD137',
        title: 'Entrust Audit: Plantillas de Applet Smart Credential Inválidas',
        category: 'Entrust OnPremise / Plantillas Smart Credentials',
        severity: 'ERROR',
        pattern: /(AUD137|Errors were detected in the Smart Credential Applet Templates)/i,
        meaning: 'Se detectaron errores en las plantillas de Applets para Tarjetas Inteligentes.',
        rootCause: 'Archivo de definición de applet JavaCard corrupto o incompatible.',
        remediation: 'Valide las plantillas de applets en el repositorio de plantillas.',
        riskLevel: 'Alto (Plantilla de Applet Invalida)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud137',
        sectionTitle: 'Código [AUD137]: Invalid Smart Credential Applet Templates'
      },
      {
        id: 'KB-ENTRUST-AUD138',
        title: 'Entrust Audit: Plantillas de Definición Smart Credential Inválidas',
        category: 'Entrust OnPremise / Plantillas Smart Credentials',
        severity: 'ERROR',
        pattern: /(AUD138|Errors were detected in the Smart Credential Definition Templates)/i,
        meaning: 'Errores en las plantillas de definición de Credenciales Inteligentes.',
        rootCause: 'Estructura XML de definición de campos inválida.',
        remediation: 'Corrija el esquema XML de la definición de credencial.',
        riskLevel: 'Alto (Plantilla de Definición Invalida)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud138',
        sectionTitle: 'Código [AUD138]: Invalid Smart Credential Definition Templates'
      },
      {
        id: 'KB-ENTRUST-AUD139',
        title: 'Entrust Audit: Plantillas de Diseño (Layout) Smart Credential Inválidas',
        category: 'Entrust OnPremise / Plantillas Smart Credentials',
        severity: 'ERROR',
        pattern: /(AUD139|Errors were detected in the Smart Credential Layout Templates)/i,
        meaning: 'Errores en las plantillas de diseño de impresión de credenciales físicas.',
        rootCause: 'Archivo de diseño visual / layout dañado.',
        remediation: 'Verifique las plantillas visuales en el módulo de impresión.',
        riskLevel: 'Alto (Plantilla de Diseño Invalida)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud139',
        sectionTitle: 'Código [AUD139]: Invalid Smart Credential Layout Templates'
      },

      // PROCEDIMIENTOS OPERATIVOS MASTER KEYS
      {
        id: 'KB-ENTRUST-SYS-KEYUPDATE',
        title: 'Entrust Procedimiento: Rotación de Claves Maestras (system keyupdate)',
        category: 'Entrust OnPremise / Operaciones de Claves Maestras',
        severity: 'INFO',
        pattern: /(system keyupdate|keyupdate -reason|master keyupdate)/i,
        meaning: 'Procedimiento de seguridad para actualizar las Claves Maestras (Master Keys) que protegen los datos sensibles en los repositorios de Entrust IdentityGuard.',
        rootCause: 'Rotación periódica de claves de cifrado o sospecha de compromiso de seguridad.',
        remediation: '1. Detenga servicios en servidor primario y réplicas.\n2. Haga backup del archivo de clave `.enc`.\n3. Ejecute `system keyupdate -reason "Motivo"` en `supersh` (sin iniciar sesión previo).\n4. Copie el nuevo `.enc` a las réplicas y ejecute `init -replica -overwrite` y `system bind`.\n5. Reinicie los servicios de IdentityGuard.',
        riskLevel: 'Medio (Procedimiento de Mantenimiento PKI)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-proc-keyupdate',
        sectionTitle: 'Procedimiento de Rotación de Master Keys & Repositorios'
      },
      {
        id: 'KB-ENTRUST-SYS-REPOUPDATE',
        title: 'Entrust Procedimiento: Re-encriptación Masiva de Repositorio (system repositoryupdate)',
        category: 'Entrust OnPremise / Operaciones de Repositorio',
        severity: 'INFO',
        pattern: /(system repositoryupdate|repositoryupdate -start|repositoryupdate -status)/i,
        meaning: 'Comando de administración para forzar la re-encriptación masiva inmediata de todos los datos en las bases de datos, LDAP y archivos de tokens de Entrust.',
        rootCause: 'Ejecución del comando `system repositoryupdate -start` en el servidor primario tras una rotación de claves maestras.',
        remediation: '1. Monitoree el estado con `system repositoryupdate -status`.\n2. Si requiere pausar, use `system repositoryupdate -stop`.\n3. Para reanudar, utilice `system repositoryupdate -resume`.',
        riskLevel: 'Bajo (Proceso de Cifrado en Segundo Plano)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-proc-keyupdate',
        sectionTitle: 'Procedimiento de Rotación de Master Keys & Repositorios'
      },

      // AUDITORÍA DE USER TOKENS ENTRUST
      {
        id: 'KB-ENTRUST-AUD2300',
        title: 'Entrust Audit: User Token Assigned (Token Asignado a Usuario)',
        category: 'Entrust OnPremise / Auditoría de User Tokens',
        severity: 'INFO',
        pattern: /(AUD2300|Token.*has been assigned to user)/i,
        meaning: 'Se asignó un token físico o de software ({0} serie {1}) a la cuenta del usuario.',
        rootCause: 'Asignación legítima de autenticador OTP por parte del administrador.',
        remediation: 'No requiere acción. Registro de auditoría de asignación.',
        riskLevel: 'Bajo (Asignación de Token)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud2300',
        sectionTitle: 'Código [AUD2300]: User Token Assigned'
      },
      {
        id: 'KB-ENTRUST-AUD2309',
        title: 'Entrust Audit: Fallo en Entrega de Transacción Soft Token (User Token Deliver Failed)',
        category: 'Entrust OnPremise / Auditoría de Soft Tokens',
        severity: 'ERROR',
        pattern: /(AUD2309|Failed delivery of transaction details for token)/i,
        meaning: 'Fallo el envío de los detalles de la transacción de verificación al token de software asignado al usuario.',
        rootCause: 'Dispositivo del usuario sin conectividad de red, servicio de notificaciones no disponible o token revocado/desactivado.',
        remediation: '1. Verifique que el dispositivo móvil o cliente Soft Token tenga acceso a red.\n2. Inicie sesión en la Consola de Administración de IdentityGuard para revisar el estado del número de serie del token.\n3. Valide el servicio de despacho de SMS/Push/Email.',
        riskLevel: 'Alto (Fallo de Transacción Fuerte / SNMP Trap Activado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud2309',
        sectionTitle: 'Código [AUD2309]: User Token Deliver Failed'
      },

      // ENTRUST IDAAS CLOUD
      {
        id: 'KB-IDAAS-SAML-401',
        title: 'Entrust IDaaS: Assertion SAML 2.0 Expirada o Firma Inválida',
        category: 'Entrust IDaaS / SSO & SAML 2.0',
        severity: 'CRITICAL',
        pattern: /(SAML_RESPONSE_EXPIRED|SAML2_SIGNATURE_INVALID|SAML_ASSERTION_FAILED)/i,
        meaning: 'El Proveedor de Identidad Cloud Entrust IDaaS rechazó la respuesta SAML 2.0 porque el sello de tiempo (NotOnOrAfter) expiró o el certificado de firma de aserción X.509 no coincide.',
        rootCause: 'Desincronización de tiempo NTP entre el servidor OnPremise/SP y la nube IDaaS, o certificado SAML expirado en la consola de IDaaS.',
        remediation: '1. Sincronice el servicio NTP del servidor OnPremise.\n2. Verifique la fecha de caducidad del certificado de firma SAML 2.0 en la Consola Entrust IDaaS.\n3. Importe el nuevo metadato XML en el Proveedor de Servicios.',
        riskLevel: 'Crítico (Bloqueo de SSO Corporativo)',
        manualVersion: 'vIDaaS',
        sectionId: 'sec-idaas-saml',
        sectionTitle: 'Guía de Troubleshooting SAML 2.0 & SSO IDaaS'
      },

      // ENTRUST IDENTITYGUARD ONPREMISE 520XXX
      {
        id: 'KB-ENTRUST-5201000',
        title: 'Entrust IdentityGuard: Server Failure (Fallo del Servidor)',
        category: 'Entrust OnPremise / Motor Principal',
        severity: 'CRITICAL',
        pattern: /(5201000|Server failure)/i,
        meaning: 'Fallo o excepción interna no controlada en el motor del servidor Entrust IdentityGuard.',
        rootCause: 'Fallo de procesamiento interno, pérdida de comunicación con la base de datos o corrupción en claves maestras.',
        remediation: '1. Reinicie el servicio de administración de Entrust (`identityguard-admin`).\n2. Verifique la conectividad con la base de datos de repositorios y valide los archivos de claves `.enc`.',
        riskLevel: 'Crítico (Fallo de Servidor)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5201000',
        sectionTitle: 'Código [5201000]: Server failure'
      },
      {
        id: 'KB-ENTRUST-5201006',
        title: 'Entrust IdentityGuard: Número de Respuestas No Coincide con Desafíos',
        category: 'Entrust OnPremise / Autenticación Grid & OTP',
        severity: 'ERROR',
        pattern: /(5201006|The number of responses to the challenge does not match)/i,
        meaning: 'El número de respuestas enviadas por el usuario o aplicación no coincide con el número de desafíos (challenges) generados.',
        rootCause: 'El usuario omitió una de las celdas de la tarjeta Grid o la aplicación integradora envió menos parámetros de los requeridos.',
        remediation: '1. Verifique que la aplicación cliente envíe exactamente el número de respuestas solicitadas por el reto Grid/OTP.\n2. Solicite al usuario ingresar todas las coordenadas solicitadas en pantalla.',
        riskLevel: 'Medio (Error de Parámetros de Autenticación)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5201006',
        sectionTitle: 'Código [5201006]: Response Count Mismatch'
      },
      {
        id: 'KB-ENTRUST-5201007',
        title: 'Entrust IdentityGuard: La Respuesta No Coincide con el Desafío',
        category: 'Entrust OnPremise / Autenticación Grid & OTP',
        severity: 'ERROR',
        pattern: /(5201007|The response to the challenge does not match the challenge)/i,
        meaning: 'La respuesta de autenticación ingresada no corresponde al desafío (challenge) o token generado.',
        rootCause: 'Valores de la tarjeta Grid o respuesta OTP errónea ingresada por el usuario.',
        remediation: '1. Verifique que el usuario esté utilizando la tarjeta Grid Card o token de software activo y correcto.\n2. Solicite generar un nuevo reto de autenticación.',
        riskLevel: 'Medio (Respuesta de Desafío Inválida)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5201007',
        sectionTitle: 'Código [5201007]: Response Mismatch'
      },
      {
        id: 'KB-ENTRUST-5201008',
        title: 'Entrust IdentityGuard: La Tarjeta No Coincide con el Desafío',
        category: 'Entrust OnPremise / Tarjetas Grid',
        severity: 'ERROR',
        pattern: /(5201008|Card does not match challenge)/i,
        meaning: 'La tarjeta Grid utilizada durante el intento de autenticación no coincide con el desafío emitido por el servidor.',
        rootCause: 'El usuario utilizó una tarjeta Grid antigua, reasignada o con número de serie diferente.',
        remediation: '1. Verifique en la consola de administración el número de serie de la tarjeta Grid activa asignada al usuario.\n2. Si la tarjeta fue extraviada, emita un nuevo paquete de tarjetas Grid y reasígnele al usuario.',
        riskLevel: 'Medio (Incompatibilidad de Tarjeta Grid)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5201008',
        sectionTitle: 'Código [5201008]: Card Does Not Match Challenge'
      },
      {
        id: 'KB-ENTRUST-5201009',
        title: 'Entrust IdentityGuard: Fallo al Generar Desafío (Failed to Generate Challenge)',
        category: 'Entrust OnPremise / Motor de Desafíos',
        severity: 'ERROR',
        pattern: /(5201009|Failed to generate challenge)/i,
        meaning: 'El servidor Entrust no pudo generar el reto o desafío de autenticación para la sesión.',
        rootCause: 'El usuario no tiene tokens ni tarjetas Grid asignadas, o la plantilla de desafíos no está configurada.',
        remediation: '1. Inicie sesión en la consola de administración de IdentityGuard y verifique que el usuario tenga un autenticador asignado.\n2. Asigne un token o tarjeta Grid al perfil del usuario.',
        riskLevel: 'Alto (Fallo de Generación de Desafío)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5201009',
        sectionTitle: 'Código [5201009]: Failed to Generate Challenge'
      },
      {
        id: 'KB-ENTRUST-5203113',
        title: 'Entrust IdentityGuard: Autenticación de Contraseña Fallida (Bad user ID or password)',
        category: 'Entrust OnPremise / Autenticación',
        severity: 'ERROR',
        pattern: /(5203113|The password authentication failed for user)/i,
        meaning: 'El subsistema de gestión de autenticaciones (IG.SYSTEM.AuthenticationManagement.API) rechazó la autenticación porque el ID de usuario o contraseña proporcionada es inválida.',
        rootCause: 'Credenciales de acceso inválidas o usuario inactivo en el directorio LDAP/Active Directory.',
        remediation: '1. Verifique que el usuario exista y esté activo en Active Directory / LDAP.\n2. Inicie sesión en la consola de Entrust para desbloquear la cuenta si superó el límite de reintentos fallidos.\n3. Solicite al usuario realizar un blanqueo o actualización de contraseña.',
        riskLevel: 'Medio (Fallo de Autenticación de Contraseña)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203113',
        sectionTitle: 'Código [5203113]: Password Authentication Failed'
      },
      {
        id: 'KB-ENTRUST-5201010',
        title: 'Entrust IdentityGuard: El PIN No Coincide con el Desafío',
        category: 'Entrust OnPremise / Autenticación PIN',
        severity: 'ERROR',
        pattern: /(5201010|PIN does not match challenge)/i,
        meaning: 'El PIN de seguridad introducido no coincide con el PIN registrado en el servidor Entrust.',
        rootCause: 'PIN de seguridad incorrecto ingresado por el usuario o la aplicación cliente.',
        remediation: '1. Solicite al usuario ingresar nuevamente su PIN de seguridad de forma precisa.\n2. Si el usuario olvidó su PIN, utilice la función de restablecimiento de PIN en la consola de administración.',
        riskLevel: 'Medio (PIN Inválido)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5201010',
        sectionTitle: 'Código [5201010]: PIN Does Not Match Challenge'
      },
      {
        id: 'KB-ENTRUST-5205079',
        title: 'Entrust IdentityGuard: Fallo de Autenticación / Credenciales Inválidas',
        category: 'Entrust OnPremise / Autenticación',
        severity: 'ERROR',
        pattern: /(5205079)/i,
        meaning: 'Fallo recurrente en el proceso de verificación de identidad. El usuario o la aplicación cliente envió credenciales o valores de autenticación no válidos.',
        rootCause: 'Intentos de inicio de sesión con contraseñas o tokens caducados, usuario bloqueado en LDAP/Active Directory o clave de API desactualizada.',
        remediation: '1. Verifique en la consola de administración de Entrust si las cuentas afectadas superaron el límite de reintentos fallidos.\n2. Revise el estado del usuario en el directorio LDAP y desbloquee la cuenta.\n3. Valide los parámetros de autenticación en la aplicación cliente integradora.',
        riskLevel: 'Medio (Error de Autenticación Reincidente)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5205079',
        sectionTitle: 'Código [5205079]: User Authentication Failure'
      },
      {
        id: 'KB-ENTRUST-5205139',
        title: 'Entrust IdentityGuard: Usuario o Alias No Encontrado',
        category: 'Entrust OnPremise / Gestión de Usuarios',
        severity: 'ERROR',
        pattern: /(5205139|Unable to find a user for user name or alias)/i,
        meaning: 'El subsistema de gestión de identidades de Entrust no pudo localizar la entidad del usuario o su alias en la base de datos ni en el almacén LDAP.',
        rootCause: 'El nombre de usuario o alias especificado en la solicitud no existe en el repositorio de identidades o no ha sido sincronizado.',
        remediation: '1. Verifique que el usuario o alias esté registrado y activo en el directorio LDAP/Active Directory.\n2. Ejecute una sincronización de repositorios desde la consola de administración de IdentityGuard.\n3. Compruebe la ortografía del nombre de usuario o alias enviado por la aplicación.',
        riskLevel: 'Medio (Usuario Inexistente)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5205139',
        sectionTitle: 'Código [5205139]: Unable to find a user for user name or alias'
      },
      {
        id: 'KB-ENTRUST-5203000',
        title: 'Entrust IdentityGuard [5203000]: Respuesta Inválida a Desafío de Autenticación (Invalid Response to Challenge)',
        category: 'Entrust OnPremise / Autenticación & Desafíos',
        severity: 'ERROR',
        pattern: /(5203000|Invalid response to a challenge)/i,
        attribution: '👤 Usuario Final / Respuesta Incorrecta',
        meaning: 'Autenticación fallida del usuario debido al ingreso de una respuesta incorrecta al desafío emitido (ej. celdas de Tarjeta Grid, Token OTP o PIN erróneo). Indica la cantidad de intentos de autenticación restantes.',
        rootCause: '1. El usuario no ingresó las respuestas correctas para el desafío emitido (Grid/OTP/PIN).\n2. Ocurrió un error interno durante la validación del desafío en el servidor Entrust.',
        remediation: '1. Ingrese las respuestas correctas para el desafío emitido sin agotar los intentos restantes.\n2. Compruebe los logs del sistema en busca de un mensaje de error contenido que pueda estar oculto para el usuario final.\n3. (Ref. Documentación Técnica Oficial Entrust IdentityGuard Release 13.0: Código 5203000 - Invalid Response to Challenge)',
        riskLevel: 'Medio (Respuesta Inválida a Desafío)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203000',
        sectionTitle: 'Código [5203000]: Invalid Response to Challenge'
      },
      {
        id: 'KB-ENTRUST-5203001',
        title: 'Entrust IdentityGuard [5203001]: Estado de Tarjeta Inválido (Invalid Card State)',
        category: 'Entrust OnPremise / Tarjetas Grid',
        severity: 'ERROR',
        pattern: /(5203001|Invalid card state)/i,
        attribution: '👤 Usuario / Estado de Tarjeta',
        meaning: 'Autenticación fallida porque la tarjeta Grid asignada al usuario se encuentra en un estado no permitido (ej. Suspendida, Revocada, Expirada o Pendiente).',
        rootCause: 'La tarjeta Grid asignada al usuario no está en estado ACTIVE en la base de datos de repositorios.',
        remediation: '1. Inicie sesión en la Consola de Administración de IdentityGuard.\n2. Revise el estado de la tarjeta Grid del usuario y cámbiela a ACTIVE o reasigne una nueva tarjeta.\n3. (Ref. Documentación Oficial Entrust Release 13.0: Código 5203001 - Invalid Card State)',
        riskLevel: 'Medio (Estado de Tarjeta Inválido)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203001',
        sectionTitle: 'Código [5203001]: Invalid Card State'
      },
      {
        id: 'KB-ENTRUST-5203002',
        title: 'Entrust IdentityGuard [5203002]: Sin Tarjeta Activa ni PIN Temporal (No Active Card or Temp PIN)',
        category: 'Entrust OnPremise / Autenticación',
        severity: 'ERROR',
        pattern: /(5203002|No active card or temporary PIN found)/i,
        attribution: '⚙️ Configuración / Asignación Incompleta',
        meaning: 'El usuario intentó autenticarse pero no posee ninguna tarjeta Grid activa ni un PIN temporal válido asignado en su perfil.',
        rootCause: 'El perfil del usuario no tiene autenticadores habilitados ni tarjetas asociadas activas.',
        remediation: '1. Ingrese a la Consola de Administración de Entrust y asigne una Tarjeta Grid o Token de Software al usuario.\n2. Si es un usuario nuevo, genere un PIN temporal de primer uso.\n3. (Ref. Documentación Oficial Entrust Release 13.0: Código 5203002 - No Active Card or Temp PIN)',
        riskLevel: 'Medio (Sin Autenticador Asignado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203002',
        sectionTitle: 'Código [5203002]: No Active Card or Temp PIN Found'
      },
      {
        id: 'KB-ENTRUST-5203003',
        title: 'Entrust IdentityGuard [5203003]: Tarjeta Grid Expirada (Card Expired)',
        category: 'Entrust OnPremise / Vigencia de Tarjetas',
        severity: 'WARN',
        pattern: /(5203003|Card expired on)/i,
        attribution: '📅 Caducidad de Credenciales',
        meaning: 'La tarjeta Grid asignada al usuario superó su fecha límite de vigencia configurada.',
        rootCause: 'Cumplimiento del periodo de caducidad estipulado en la política de tarjetas del grupo.',
        remediation: '1. Emita y asigne un nuevo paquete de Tarjetas Grid para el usuario.\n2. Verifique las políticas de vigencia en la consola de administración.\n3. (Ref. Documentación Oficial Entrust Release 13.0: Código 5203003 - Card Expired)',
        riskLevel: 'Medio (Tarjeta Caducada)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203003',
        sectionTitle: 'Código [5203003]: Card Expired'
      },
      {
        id: 'KB-ENTRUST-5203004',
        title: 'Entrust IdentityGuard [5203004]: Usuario No Encontrado para Autenticación (User Not Found)',
        category: 'Entrust OnPremise / Identidad de Usuarios',
        severity: 'ERROR',
        pattern: /(5203004|User.*was not found and cannot be used for authentication)/i,
        attribution: '👤 Usuario Final / ID Inexistente',
        meaning: 'El identificador de usuario proporcionado no fue localizado en el repositorio de Entrust ni en Active Directory / LDAP.',
        rootCause: 'Nombre de usuario mal escrito en el portal o usuario desaprovisionado del directorio.',
        remediation: '1. Verifique la ortografía del ID de usuario enviado por la aplicación integradora.\n2. Verifique que el usuario esté activo e inscrito en la Consola Entrust.\n3. (Ref. Documentación Oficial Entrust Release 13.0: Código 5203004 - User Not Found)',
        riskLevel: 'Medio (Usuario Inexistente)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203004',
        sectionTitle: 'Código [5203004]: User Not Found'
      },
      {
        id: 'KB-ENTRUST-5203005',
        title: 'Entrust IdentityGuard [5203005]: PIN Temporal Expirado (Temporary PIN Expired)',
        category: 'Entrust OnPremise / Autenticación PIN',
        severity: 'WARN',
        pattern: /(5203005|Temporary PIN expired on)/i,
        attribution: '⌛ Expiración de PIN Temporal',
        meaning: 'El PIN de seguridad temporal otorgado al usuario venció antes de su primer uso.',
        rootCause: 'Excedido el tiempo de validez fijado para el PIN de enrolamiento.',
        remediation: '1. Genere un nuevo PIN temporal desde la Consola de Administración de IdentityGuard.\n2. Inste al usuario a completar el primer inicio de sesión sin demoras.\n3. (Ref. Documentación Oficial Entrust Release 13.0: Código 5203005 - Temp PIN Expired)',
        riskLevel: 'Bajo (PIN Temporal Vencido)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203005',
        sectionTitle: 'Código [5203005]: Temporary PIN Expired'
      },
      {
        id: 'KB-ENTRUST-5207005',
        title: 'Entrust IdentityGuard [5207005]: Sesión Administrativa Expirada (Login Session Timed Out)',
        category: 'Entrust OnPremise / Consola de Administración',
        severity: 'WARN',
        pattern: /(5207005|Login session has timed out)/i,
        attribution: '⏱️ Consola de Administración / Timeout',
        meaning: 'La sesión activa del administrador en la Consola de Administración de Entrust fue cerrada automáticamente por inactividad.',
        rootCause: 'Excedido el tiempo máximo de inactividad permitido para la consola web.',
        remediation: '1. Inicie sesión nuevamente en la Consola de Administración de Entrust IdentityGuard.\n2. Ajuste el tiempo de inactividad en la configuración de la consola si es necesario.\n3. (Ref. Documentación Oficial Entrust Release 13.0: Código 5207005 - Session Timed Out)',
        riskLevel: 'Bajo (Timeout de Sesión Administrativa)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5207005',
        sectionTitle: 'Código [5207005]: Login Session Timed Out'
      },
      {
        id: 'KB-ENTRUST-5203016',
        title: 'Entrust IdentityGuard: Cuenta de Usuario Bloqueada (Too Many Failed Attempts)',
        category: 'Entrust OnPremise / Control de Acceso',
        severity: 'ERROR',
        pattern: /(5203016)/i,
        meaning: 'La cuenta del usuario fue bloqueada automáticamente por exceder el número máximo de reintentos fallidos de autenticación permitidos.',
        rootCause: 'Múltiples reintentos fallidos consecutivos de contraseña, PIN o tarjetas Grid por parte del usuario o un ataque de fuerza bruta.',
        remediation: '1. Desbloquee la cuenta del usuario desde la Consola de Administración de IdentityGuard.\n2. Verifique la causa de los reintentos y, si es necesario, proceda al blanqueo o restablecimiento de su credencial.',
        riskLevel: 'Alto (Cuenta Bloqueada por Reintentos Fallidos)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203016',
        sectionTitle: 'Código [5203016]: User Account Locked'
      },
      {
        id: 'KB-ENTRUST-5202340',
        title: 'Entrust IdentityGuard: Fallo de Autorización de Aplicación Cliente',
        category: 'Entrust OnPremise / Integración API',
        severity: 'ERROR',
        pattern: /(5202340)/i,
        meaning: 'La aplicación cliente o canal integrador fue rechazado al intentar consumir las APIs web de Entrust IdentityGuard.',
        rootCause: 'Clave de API de aplicación cliente (Client Shared Secret) incorrecta, certificado caducado o IP de origen no autorizada.',
        remediation: '1. Verifique las credenciales de la aplicación cliente en la consola de administración de Entrust.\n2. Revise la lista de Direcciones IP autorizadas en la política del canal de integración.',
        riskLevel: 'Alto (Fallo de Autorización de Canal API)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5202340',
        sectionTitle: 'Código [5202340]: Client Application Authorization Failure'
      },
      {
        id: 'KB-ENTRUST-5203020',
        title: 'Entrust IdentityGuard: Contraseña de Usuario Expirada',
        category: 'Entrust OnPremise / Políticas de Contraseñas',
        severity: 'WARN',
        pattern: /(5203020)/i,
        meaning: 'La contraseña o secreto del usuario ha vencido según la política de caducidad vigente.',
        rootCause: 'Cumplimiento del tiempo límite de validez de la contraseña establecido en la política de grupo de Entrust.',
        remediation: '1. Inste al usuario a realizar el cambio de contraseña a través del portal de autoservicio.\n2. Restablezca la vigencia de la clave en el directorio LDAP/Active Directory.',
        riskLevel: 'Medio (Contraseña Expirada)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203020',
        sectionTitle: 'Código [5203020]: Password Policy Violation / Expired'
      },
      {
        id: 'KB-ENTRUST-5207677',
        title: 'Entrust IdentityGuard: Fallo de Comunicación con Proxy RADIUS',
        category: 'Entrust OnPremise / Proxy RADIUS',
        severity: 'ERROR',
        pattern: /(5207677)/i,
        meaning: 'Perdida de conectividad o tiempo de espera agotado en la comunicación entre el Agente RADIUS y el Servicio de Autenticación de Entrust.',
        rootCause: 'Servicio RADIUS detenido, puerto UDP 1812/1813 bloqueado en firewall o timeout de respuesta.',
        remediation: '1. Verifique que el servicio `identityguard-radius` esté activo.\n2. Compruebe las reglas de firewall y la conectividad de red entre el concentrador VPN y el servidor Entrust.',
        riskLevel: 'Crítico (Fallo de Proxy RADIUS)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5207677',
        sectionTitle: 'Código [5207677]: RADIUS Proxy Communication Failure'
      },
      {
        id: 'KB-ENTRUST-5209525',
        title: 'Entrust IdentityGuard: Fallo de Despacho Notificación Push / Soft Token',
        category: 'Entrust OnPremise / Soft Tokens & Push',
        severity: 'ERROR',
        pattern: /(5209525)/i,
        meaning: 'El servidor no pudo entregar la transacción o la notificación Push MFA al dispositivo móvil del usuario.',
        rootCause: 'Dispositivo del usuario sin señal/internet, token de notificación caducado o fallo en la pasarela Apple APNS / Google FCM.',
        remediation: '1. Verifique que el dispositivo móvil del usuario tenga acceso a internet.\n2. En la consola de administración, valide el estado del Soft Token y re-asócielo al dispositivo si es necesario.',
        riskLevel: 'Alto (Fallo de Notificación Push MFA)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5209525',
        sectionTitle: 'Código [5209525]: Push Notification Delivery Failure'
      },
      {
        id: 'KB-ENTRUST-5202013',
        title: 'Entrust IdentityGuard: ID de Usuario o Contraseña Inválida',
        category: 'Entrust OnPremise / Autenticación',
        severity: 'ERROR',
        pattern: /(5202013|Invalid user ID or password)/i,
        meaning: 'El subsistema de Contexto de Sistema de Entrust IdentityGuard (IG.SYSTEM.SystemContext.API) rechazó la autenticación porque el ID de usuario o contraseña es incorrecta.',
        rootCause: 'Credenciales inválidas ingresadas por el usuario, usuario bloqueado en LDAP/Active Directory o clave de API incorrecta.',
        remediation: '1. Verifique que el usuario exista y esté activo en Active Directory / LDAP.\n2. Inicie sesión en la consola de administración de IdentityGuard para revisar el estado del usuario.\n3. Desbloquee la cuenta si superó el límite de reintentos fallidos.',
        riskLevel: 'Medio (Fallo de Autenticación)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5202013',
        sectionTitle: 'Código [5202013]: Invalid user ID or password'
      }
    ];

    this.rules = this.loadRules();
  }

  loadRules() {
    try {
      const saved = localStorage.getItem(this.storageKey);
      if (saved) {
        const customRules = JSON.parse(saved);
        const parsedCustom = customRules.map(r => ({
          ...r,
          pattern: new RegExp(r.patternSource || r.pattern, r.patternFlags || 'i')
        }));
        return [...this.defaultRules, ...parsedCustom];
      }
    } catch (e) {
      console.warn('Error al cargar reglas personalizadas de localStorage:', e);
    }
    return [...this.defaultRules];
  }

  saveCustomRule(rule) {
    try {
      const currentCustom = this.getCustomRulesOnly();
      const patternString = rule.pattern instanceof RegExp ? rule.pattern.source : rule.pattern;
      const flags = rule.pattern instanceof RegExp ? rule.pattern.flags : 'i';

      const newCustomRule = {
        id: rule.id || `KB-CUST-${Date.now().toString().slice(-4)}`,
        title: rule.title,
        category: rule.category || 'Entrust / Regla Personalizada',
        severity: rule.severity || 'ERROR',
        patternSource: patternString,
        patternFlags: flags,
        pattern: new RegExp(patternString, flags),
        meaning: rule.meaning,
        rootCause: rule.rootCause,
        remediation: rule.remediation,
        riskLevel: rule.riskLevel || 'Medio',
        manualVersion: rule.manualVersion || 'vEntrust',
        sectionId: rule.sectionId || 'sec-5202013',
        sectionTitle: rule.sectionTitle || 'Catálogo de Errores Entrust IdentityGuard'
      };

      currentCustom.push(newCustomRule);
      localStorage.setItem(this.storageKey, JSON.stringify(currentCustom.map(r => ({
        ...r,
        pattern: r.patternSource
      }))));

      this.rules.push(newCustomRule);
      return newCustomRule;
    } catch (e) {
      console.error('Error guardando regla en KB:', e);
      throw e;
    }
  }

  getCustomRulesOnly() {
    try {
      const saved = localStorage.getItem(this.storageKey);
      return saved ? JSON.parse(saved) : [];
    } catch (e) {
      return [];
    }
  }

  diagnoseLog(logText, targetCode) {
    if (!logText && !targetCode) return null;
    const searchText = logText || (targetCode ? `[${targetCode}]` : '');

    // Si se especificó un código objetivo, buscar primero la regla que coincida de forma estricta con ese código
    if (targetCode) {
      const specRule = this.rules.find(r => r.id === `KB-ENTRUST-${targetCode}` || r.pattern.test(`[${targetCode}]`));
      if (specRule) {
        return {
          matched: true,
          ruleId: specRule.id,
          title: specRule.title,
          category: specRule.category,
          severity: specRule.severity,
          meaning: specRule.meaning,
          rootCause: specRule.rootCause,
          remediation: specRule.remediation,
          riskLevel: specRule.riskLevel,
          manualVersion: specRule.manualVersion,
          sectionId: specRule.sectionId,
          sectionTitle: specRule.sectionTitle
        };
      }
    }

    for (const rule of this.rules) {
      if (rule.pattern.test(searchText)) {
        return {
          matched: true,
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          meaning: rule.meaning,
          rootCause: rule.rootCause,
          remediation: rule.remediation,
          riskLevel: rule.riskLevel,
          manualVersion: rule.manualVersion,
          sectionId: rule.sectionId,
          sectionTitle: rule.sectionTitle
        };
      }
    }

    // Diagnóstico Heurístico Entrust OnPremise AUDxxxx (Sin mensajes de "Consulte el manual")
    const audMatch = searchText.match(/\[(AUD\d+)\]\s*(.*)/i);
    if (audMatch) {
      const audCode = targetCode || audMatch[1].toUpperCase();
      const audDetail = audMatch[2] ? audMatch[2].trim() : 'Evento de auditoría en la plataforma Entrust.';
      return {
        matched: true,
        ruleId: `KB-ENTRUST-${audCode}`,
        title: `Entrust Audit: Evento [${audCode}]`,
        category: 'Entrust OnPremise Audit',
        severity: 'INFO',
        meaning: `Se registró el evento de auditoría [${audCode}] en el módulo IG.AUDIT: ${audDetail}`,
        rootCause: 'Operación o cambio de estado ejecutado por un usuario, administrador o tarea programada.',
        remediation: '1. Verifique que el evento corresponda a una actividad autorizada en el sistema.\n2. En caso de ser una alerta de conexión o servicio, revise la conectividad del componente afectado.',
        riskLevel: 'Bajo (Registro de Auditoría)',
        manualVersion: 'vEntrust',
        sectionId: `sec-${audCode.toLowerCase()}`,
        sectionTitle: `Código [${audCode}]: Evento de Auditoría Entrust`
      };
    }

    // Diagnóstico Heurístico Entrust OnPremise 520xxx (Remediación técnica explícita)
    const regexToUse = targetCode ? new RegExp('\\[(' + targetCode + ')\\]\\s*(.*)', 'i') : /\[(520\d{4})\]\s*(.*)/;
    const entrustMatch = searchText.match(regexToUse) || searchText.match(/\[(520\d{4})\]\s*(.*)/);
    if (entrustMatch) {
      const code = targetCode || entrustMatch[1];
      const detail = entrustMatch[2] ? entrustMatch[2].trim() : 'Error en la transacción de autenticación/administración.';

      let causeText = 'Fallo reportado por el servidor de autenticación/administración de Entrust IdentityGuard.';
      let remediationText = '1. Revise el estado de la cuenta del usuario y sus credenciales activas en la consola de Entrust.\n2. Compruebe si el usuario o token alcanzó el límite de reintentos fallidos y desbloquee la cuenta.\n3. Valide la conectividad y sincronización entre el servidor web y la base de datos de repositorios.';

      if (/PIN/i.test(detail)) {
        causeText = 'El PIN de seguridad proporcionado por el usuario no coincide con el PIN registrado en el servidor Entrust.';
        remediationText = '1. Solicite al usuario ingresar nuevamente su PIN de seguridad o restablecerlo en la consola.\n2. Verifique si la cuenta del usuario fue bloqueada por intentos fallidos de PIN.';
      } else if (/Card|Grid/i.test(detail)) {
        causeText = 'La tarjeta Grid Card o valor de desafío ingresado por el usuario no corresponde al número de serie asignado.';
        remediationText = '1. Verifique en la consola de administración el número de serie de la tarjeta Grid activa asignada al usuario.\n2. Si la tarjeta fue extraviada o reemplazada, asigne un nuevo paquete de tarjetas Grid.';
      } else if (/Challenge|response/i.test(detail)) {
        causeText = 'La respuesta de desafío ingresada no coincide con el reto numérico (challenge) emitido por el servidor.';
        remediationText = '1. Solicite al usuario generar una nueva respuesta al desafío (Challenge-Response).\n2. Verifique la sincronización de tiempo (NTP) del servidor y del cliente.';
      } else if (/password|user ID|login/i.test(detail)) {
        causeText = 'Credenciales de acceso inválidas o usuario inactivo en el directorio LDAP/Active Directory.';
        remediationText = '1. Verifique que el nombre de usuario exista y esté activo en Active Directory.\n2. Restablezca la contraseña o desbloquee al usuario en la consola de administración.';
      } else if (/server failure|5201000/i.test(detail) || code === '5201000') {
        causeText = 'Excepción o fallo interno del motor de servidor de Entrust IdentityGuard durante el procesamiento de la transacción.';
        remediationText = '1. Reinicie el servicio de administración de Entrust (`identityguard-admin`).\n2. Verifique la conectividad con la base de datos principal y los archivos de clave maestra (`.enc`).';
      }

      return {
        matched: true,
        ruleId: `KB-ENTRUST-${code}`,
        title: `Entrust IdentityGuard Error [${code}]`,
        category: 'Entrust OnPremise Suite',
        severity: 'ERROR',
        meaning: `Se registró el código de error [${code}]: ${detail}`,
        rootCause: causeText,
        remediation: remediationText,
        riskLevel: 'Medio (Error de Sistema IdentityGuard)',
        manualVersion: 'vEntrust',
        sectionId: `sec-${code}`,
        sectionTitle: `Código [${code}]: Error Entrust IdentityGuard`
      };
    }

    // Diagnóstico Heurístico Entrust (Adaptable OnPremise / Cloud)
    if (/IDaaS|SAML|OIDC|OAuth2|Push|MFA|Radius/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-ENTRUST-MFA',
        title: 'Evento de Autenticación / Federación Entrust',
        category: 'Entrust IdentityGuard Suite',
        severity: /failed|error|rejected|timeout/i.test(logText) ? 'ERROR' : 'INFO',
        attribution: '🔒 Servicios de Identidad & Federación',
        meaning: 'Registro de evento de autenticación, token o evaluación de regla MFA en la plataforma Entrust.',
        rootCause: 'Solicitud de token, sincronización de identidad o evaluación de política MFA.',
        remediation: '1. Verifique el estado de la política de autenticación en la Consola Entrust.\n2. Compruebe la validez del certificado SAML 2.0 / OIDC.\n3. Verifique la conectividad con la pasarela MFA.',
        riskLevel: 'Medio (Evento de Identidad)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-idaas-saml',
        sectionTitle: 'Manual de Diagnóstico Entrust IdentityGuard'
      };
    }

    // Diagnóstico heurístico para logs de Tomcat / Catalina (Servidor de Aplicaciones Entrust)
    if (/OutOfMemoryError|Java heap space/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-CATALINA-OOM',
        title: 'Tomcat Catalina: OutOfMemoryError (Agotamiento de Memoria JVM Heap)',
        category: 'Tomcat Catalina / Servidor de Aplicaciones',
        severity: 'CRITICAL',
        meaning: 'La máquina virtual Java (JVM) de Tomcat que ejecuta Entrust IdentityGuard agotó su memoria RAM disponible.',
        rootCause: 'Asignación insuficiente del tamaño de Heap (-Xmx) en Tomcat o alta concurrencia de sesiones de autenticación.',
        remediation: '1. Aumente la memoria JVM en setenv.sh / catalina.sh (ej. -Xms2048m -Xmx4096m).\n2. Reinicie el servicio Tomcat/IdentityGuard.\n3. Monitoree la recolección de basura (GC) con jstat / VisualVM. (Ref. Manual Entrust IDG Tomcat Tuning: Sección 9.3 - JVM Heap Settings)',
        riskLevel: 'Crítico (Caída del Servidor de Aplicaciones)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud-codes',
        sectionTitle: 'Manual de Ajuste JVM y Servidor Tomcat'
      };
    }

    if (/SQLException|Cannot get a connection|ConnectionPool/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-CATALINA-JDBC',
        title: 'Tomcat Catalina: Fallo de Conexión a Base de Datos (JDBC Connection Pool)',
        category: 'Tomcat Catalina / Base de Datos',
        severity: 'CRITICAL',
        meaning: 'El contenedor de servlets Tomcat no pudo obtener una conexión activa con la base de datos SQL de Entrust.',
        rootCause: 'Pool de conexiones JDBC agotado (maxActive alcanzado) o caída del servidor de base de datos SQL.',
        remediation: '1. Incremente maxActive y maxWaitSec en context.xml / server.xml de Tomcat.\n2. Verifique la conectividad de red con el puerto SQL (ej. 1433/1521/5432).\n3. Reinicie el pool de conexiones. (Ref. Manual de Administración Entrust: Sección 7.1 - Tomcat JDBC Connection Pooling)',
        riskLevel: 'Alto (Base de Datos Inalcanzable)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud154',
        sectionTitle: 'Manual de Configuración de Pool JDBC Tomcat'
      };
    }

    if (/SSLHandshakeException|PKIX path building failed/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-CATALINA-SSL',
        title: 'Tomcat Catalina: Fallo de Certificado TLS/SSL (PKIX CertPath Builder Failed)',
        category: 'Tomcat Catalina / Seguridad SSL',
        severity: 'ERROR',
        meaning: 'Tomcat no pudo validar la cadena de confianza del certificado SSL/TLS al conectar con un directorio LDAP o IDaaS Cloud.',
        rootCause: 'Falta el certificado CA raíz o intermedio en el Keystore / Truststore (cacerts) de la JVM de Tomcat.',
        remediation: '1. Importe el certificado CA usando: keytool -importcert -keystore $JAVA_HOME/lib/security/cacerts -alias entrust-ca -file ca-cert.crt.\n2. Reinicie Tomcat para recargar la cadena de certificados SSL. (Ref. Guía de Seguridad Entrust TLS: Sección 6.2 - Keystore Management)',
        riskLevel: 'Alto (Conexión TLS Rechazada)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud125',
        sectionTitle: 'Guía de Certificados SSL/TLS en Tomcat'
      };
    }

    if (/ClientAbortException|Broken pipe/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-CATALINA-CLIENT-ABORT',
        title: 'Tomcat Catalina: Cancelación de Conexión Cliente (ClientAbortException)',
        category: 'Tomcat Catalina / Red & Proxy',
        severity: 'WARN',
        meaning: 'El proxy inverso (Nginx / F5 / NetScaler) o el usuario cerró la conexión socket antes de recibir la respuesta.',
        rootCause: 'Tiempo de espera (timeout) muy corto en el proxy inverso o abandono del usuario durante la transacción.',
        remediation: '1. Incremente proxy_read_timeout y proxy_connect_timeout a 60s en Nginx/Apache.\n2. Ajuste connectionTimeout="20000" en server.xml de Tomcat. (Ref. Manual de Arquitectura Entrust Web Proxy: Sección 4.5 - Reverse Proxy Tuning)',
        riskLevel: 'Medio (Timeout de Conexión Proxy)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud126',
        sectionTitle: 'Guía de Proxy Inverso y Timeouts HTTP'
      };
    }

    // Diagnóstico heurístico para Web Services SOAP de Entrust IdentityGuard
    if (/soapenv:Fault|SOAPFault|wsse:FailedAuthentication|AuthenticationService|AdministrationService/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-SOAP-IDG',
        title: 'Entrust IDG: Excepción en Web Service SOAP (Authentication / Administration API)',
        category: 'Entrust OnPremise / Web Services SOAP',
        severity: /Fault|FailedAuthentication|ERROR|500/i.test(logText) ? 'ERROR' : 'INFO',
        attribution: '🖥️ Cliente SOAP / Integración de Aplicación',
        meaning: 'Transacción rechazada o excepción registrada en los puntos de enlace SOAP (WSDL) de Entrust IdentityGuard.',
        rootCause: 'Firma WS-Security inválida, credenciales del cliente SOAP incorrectas, o excepción en la lógica del servicio web.',
        remediation: '1. Revise el elemento <wsse:Security> y el Password Digest en el mensaje SOAP de la solicitud.\n2. Verifique en la Consola Entrust > Web Services Clients la vigencia de la clave del canal.\n3. (Ref. Guía de Integración Entrust SOAP Web Services: Sección 4.1 - WS-Security & WSDL Specifications)',
        riskLevel: 'Alto (Rechazo en API SOAP)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud-codes',
        sectionTitle: 'Manual de Integración SOAP Web Services Entrust'
      };
    }

    // Diagnóstico especializado de Códigos de Estado HTTP (200, 400, 401, 403, 404, 429, 500, 502, 503, 504)
    const httpStatusMatch = logText.match(/"\s+(200|201|400|401|403|404|429|500|502|503|504)\s+\d+/i) ||
                            logText.match(/\bHTTP\/\d\.\d"\s+(200|201|400|401|403|404|429|500|502|503|504)\b/i) ||
                            logText.match(/\b(200|201|400|401|403|404|429|500|502|503|504)\b/);

    if (httpStatusMatch) {
      const code = httpStatusMatch[1];

      if (code === '400') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-400',
          title: 'HTTP 400 Bad Request: Solicitud API Mal Formada o Parámetros Inválidos',
          category: 'HTTP Protocol / Error de Cliente API',
          severity: 'ERROR',
          attribution: '⚠️ Aplicación Cliente / Integración Frontend',
          meaning: 'El cliente web o la aplicación móvil envió una petición HTTP con sintaxis incorrecta, formato JSON/XML inválido o parámetros requeridos ausentes.',
          rootCause: 'Parámetros obligatorios ausentes en el Query String (ej. uid, pwd, login o aleatorio faltantes) o cuerpo HTTP mal formado.',
          remediation: '1. Valide el formato de los parámetros enviados a los endpoints /idgserv/action/rest/.\n2. Asegure la codificación de caracteres URL (URL encoding) de los parámetros.\n3. (Ref. Guía de Integración REST API Entrust: Sección 3.2 - HTTP Error Codes)',
          riskLevel: 'Medio (Rechazo por Formato de Solicitud)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '401') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-401',
          title: 'HTTP 401 Unauthorized: No Autorizado / Credenciales o Token Inválidos',
          category: 'HTTP Protocol / Autenticación de Cliente',
          severity: 'ERROR',
          attribution: '👤 Usuario Final / Aplicación Cliente',
          meaning: 'La petición carece de credenciales de autenticación válidas, el token OAuth2/JWT está caducado o el secreto de API es incorrecto.',
          rootCause: 'Clave API de aplicación caducada, token de sesión vencido o firma de solicitud rechazada por el servidor.',
          remediation: '1. Solicite un nuevo Bearer Token OAuth2 a la API de Entrust IDaaS/IDG.\n2. Compruebe la vigencia del Client Secret del canal cliente.\n3. (Ref. Guía de Seguridad Entrust API: Sección 2.1 - Bearer Token Authentication)',
          riskLevel: 'Alto (Fallo de Autenticación API)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '403') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-403',
          title: 'HTTP 403 Forbidden: Acceso Prohibido / Permisos Insuficientes',
          category: 'HTTP Protocol / Autorización & Políticas',
          severity: 'ERROR',
          attribution: '🛡️ Política de Seguridad / Permisos de Usuario',
          meaning: 'El servidor comprendió la solicitud pero se niega a autorizarla según las políticas de acceso de Entrust.',
          rootCause: 'El usuario o aplicación cliente autenticada carece del rol necesario o viola una regla de política MFA.',
          remediation: '1. Verifique los grupos de autorización asignados al usuario o canal.\n2. Revise las políticas de acceso en la Consola Entrust (Authentication Policies).\n3. (Ref. Manual de Administración Entrust: Sección 4.3 - Access Control Rules)',
          riskLevel: 'Alto (Acceso Denegado por Política)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '404') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-404',
          title: 'HTTP 404 Not Found: Endpoint o Recurso No Encontrado',
          category: 'HTTP Protocol / Error de Ruta Client-side',
          severity: 'WARN',
          attribution: '⚠️ Aplicación Cliente (Ruta URL Incorrecta)',
          meaning: 'El punto de enlace URL solicitado no existe en el servidor Tomcat o el recurso indicado no fue localizado.',
          rootCause: 'Error tipográfico en la URI de la llamada API REST (ej. ruta incorrecta en /idgserv/action/rest/) o servlet desinstalado.',
          remediation: '1. Verifique que el context path /idgserv/ esté desplegado activamente en Tomcat.\n2. Confirme que la ruta del endpoint coincida exactamente con la documentación OpenAPI/Swagger de Entrust.\n3. (Ref. Guía de Integración REST API Entrust: Sección 1.4 - API Endpoints Overview)',
          riskLevel: 'Bajo (Ruta Inexistente)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '429') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-429',
          title: 'HTTP 429 Too Many Requests: Límite de Tasa Superado (Rate Limiting)',
          category: 'HTTP Protocol / Protección Anti-Bruteforce',
          severity: 'WARN',
          attribution: '⚡ Script de Cliente / Consumo Excesivo',
          meaning: 'Se enviaron más solicitudes por segundo de las permitidas por la política de protección anti-fuerza bruta de Entrust.',
          rootCause: 'Bucle descontrolado en la aplicación cliente o intento de escaneo masivo sobre los endpoints de autenticación.',
          remediation: '1. Implemente reintentos con retardo exponencial (exponential backoff & jitter) en el cliente.\n2. Ajuste los límites de tasa (Rate Limit Thresholds) en la Consola Entrust IDaaS.\n3. (Ref. Guía de Protección Entrust API: Sección 8.1 - Rate Limiting & Throttling)',
          riskLevel: 'Medio (Límite de Tasa Alcanzado)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '500') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-500',
          title: 'HTTP 500 Internal Server Error: Fallo Interno en Servidor Entrust / Tomcat',
          category: 'HTTP Protocol / Error Crítico de Servidor',
          severity: 'CRITICAL',
          attribution: '🖥️ Servidor Entrust / Tomcat / Base de Datos',
          meaning: 'El servidor de aplicaciones Tomcat experimentó un fallo no manejado o la API no pudo comunicarse con la base de datos de repositorios.',
          rootCause: 'Excepción Java no capturada (SQLException / OutOfMemoryError / NullPointerException) o agotamiento del pool JDBC.',
          remediation: '1. Revise catalina.out y los logs de aplicación a la hora exacta del incidente.\n2. Verifique la conectividad con la base de datos repositorio y amplíe el pool JDBC en context.xml.\n3. (Ref. Manual de Administración Entrust: Sección 7.1 - Database Connection Pooling)',
          riskLevel: 'Crítico (Fallo de Respuesta API Backend)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '502' || code === '503') {
        return {
          matched: true,
          ruleId: `KB-HTTP-${code}`,
          title: `HTTP ${code}: Servicio No Disponible / Proxy Inverso Desconectado`,
          category: 'HTTP Protocol / Infraestructura & Proxy',
          severity: 'CRITICAL',
          attribution: '🔌 Proxy Inverso (Nginx/Apache) / Servicio Tomcat Caído',
          meaning: 'El balanceador de carga o proxy inverso no pudo conectar con el servidor Tomcat de Entrust o el servicio está detenido.',
          rootCause: 'Servicio Tomcat7 detenido, proceso Java colgado por falta de memoria o puerto 8080/8443 inalcanzable.',
          remediation: '1. Verifique el estado del servicio Tomcat7 mediante: systemctl status tomcat.\n2. Verifique la pila de procesos Java y reinicie el servicio de ser necesario.\n3. (Ref. Guía de Mantenimiento Entrust Infrastructure: Sección 3.2 - Service Recovery)',
          riskLevel: 'Crítico (Servicio Web Caído)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '504') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-504',
          title: 'HTTP 504 Gateway Timeout: Tiempo de Espera Agotado en Backend',
          category: 'HTTP Protocol / Timeouts de Infraestructura',
          severity: 'ERROR',
          attribution: '⏳ Servidor Backend Entrust / Latencia de Base de Datos',
          meaning: 'El proxy inverso no recibió una respuesta oportuna del servidor Tomcat antes de que expirara el tiempo de espera (timeout).',
          rootCause: 'Consultas SQL extremadamente lentas en la base de datos o bloqueos de transacciones en la JVM de Tomcat.',
          remediation: '1. Incremente proxy_read_timeout 60s; en Nginx/Apache.\n2. Analice las consultas lentas en la base de datos de repositorios Entrust.\n3. (Ref. Manual Entrust Web Proxy: Sección 4.5 - Timeout Adjustments)',
          riskLevel: 'Alto (Timeout de Respuesta Backend)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }

      if (code === '200' || code === '201') {
        return {
          matched: true,
          ruleId: 'KB-HTTP-200',
          title: `HTTP ${code} OK: Operación API Procesada Exitosamente`,
          category: 'HTTP Protocol / Respuesta Exitosa',
          severity: 'INFO',
          attribution: '✅ Operación Normal / Petición Válida',
          meaning: 'La solicitud HTTP enviada a la API REST de Entrust fue recibida, procesada y respondida sin errores.',
          rootCause: 'Funcionamiento correcto del canal API y procesamiento sin excepciones.',
          remediation: 'No se requiere acción correctiva. La transacción completó de forma nominal.',
          riskLevel: 'Ninguno (Operación Nominal Exitosamente Completada)',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Guía de Errores HTTP REST Entrust'
        };
      }
    }

    // Diagnóstico heurístico general
    if (/error|fail|exception|fatal|panic|critical|500/i.test(logText)) {
      return {
        matched: false,
        ruleId: 'KB-GEN-999',
        title: 'Excepción o Fallo Crítico Registrado en Servidor Entrust',
        category: 'Detección Heurística General',
        severity: /fatal|panic|critical|500/i.test(logText) ? 'CRITICAL' : 'ERROR',
        attribution: '🖥️ Servidor Entrust / Backend Application',
        meaning: 'Se detectó un fallo crítico o excepción en la ejecución de la solicitud. El mensaje contiene términos de error o respuesta HTTP 500.',
        rootCause: 'Condición de fallo en la ejecución del servicio web o excepción de aplicación en Tomcat/Java.',
        remediation: '1. Inspeccione la traza completa (Stacktrace) en catalina.out a la hora exacta del evento.\n2. Verifique la conectividad con los repositorios de base de datos.',
        riskLevel: 'Alto (Fallo de Servicio)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud-codes',
        sectionTitle: 'Manual Administrativo Operativo'
      };
    }

    return {
      matched: false,
      ruleId: 'KB-INFO-000',
      title: 'Evento Operativo Normal',
      category: 'Informativo',
      severity: 'INFO',
      attribution: '✅ Operación Normal del Sistema',
      meaning: 'Registro de actividad estándar o estado transitorio sin indicios de fallos críticos en el sistema.',
      rootCause: 'Ejecución regular de tareas programadas, accesos autorizados o señales de salud.',
      remediation: 'No requiere ninguna acción correctiva inmediata.',
      riskLevel: 'Bajo (Sin Riesgo)',
      manualVersion: 'vEntrust',
      sectionId: 'sec-aud-codes',
      sectionTitle: 'Manual Administrativo Operativo'
    };
  }

  getAllRules() {
    return this.rules;
  }
}

window.knowledgeBaseEngine = new KnowledgeBase();
