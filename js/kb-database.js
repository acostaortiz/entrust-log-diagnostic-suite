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

  diagnoseLog(logText) {
    if (!logText) return null;

    for (const rule of this.rules) {
      if (rule.pattern.test(logText)) {
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
    const audMatch = logText.match(/\[(AUD\d+)\]\s*(.*)/i);
    if (audMatch) {
      const audCode = audMatch[1].toUpperCase();
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
    const entrustMatch = logText.match(/\[(520\d{4})\]\s*(.*)/);
    if (entrustMatch) {
      const code = entrustMatch[1];
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

    // Diagnóstico Heurístico Entrust IDaaS Cloud (Remediación técnica explícita)
    if (/IDaaS|SAML|OIDC|OAuth2|Push|MFA|Radius/i.test(logText)) {
      return {
        matched: true,
        ruleId: 'KB-IDAAS-GEN',
        title: 'Evento de Autenticación Cloud Entrust IDaaS',
        category: 'Entrust IDaaS Cloud Suite',
        severity: /failed|error|rejected|timeout/i.test(logText) ? 'ERROR' : 'INFO',
        meaning: 'Registro de evento de autenticación en la nube o pasarela de identidad Entrust IDaaS.',
        rootCause: 'Solicitud de token, sincronización de identidad o evaluación de regla MFA en la nube.',
        remediation: '1. Verifique el estado del tenant y la política de autenticación en la Consola Entrust IDaaS Cloud.\n2. Compruebe la validez del certificado SAML 2.0 / OIDC.\n3. Verifique la conectividad con la pasarela MFA.',
        riskLevel: 'Medio (Evento de Identidad Cloud)',
        manualVersion: 'vIDaaS',
        sectionId: 'sec-idaas-saml',
        sectionTitle: 'Manual de Diagnóstico Entrust IDaaS Cloud'
      };
    }

    // Diagnóstico heurístico general
    if (/error|fail|exception|fatal|panic/i.test(logText)) {
      return {
        matched: false,
        ruleId: 'KB-GEN-999',
        title: 'Anomalía o Error Generado en Sistema',
        category: 'Detección Heurística General',
        severity: /fatal|panic|critical/i.test(logText) ? 'CRITICAL' : 'ERROR',
        meaning: 'Se detectó una palabra clave de fallo en el log. El mensaje contiene términos de error o excepción que requieren revisión.',
        rootCause: 'Condición de fallo en ejecución de servicio o excepción no capturada en el flujo de aplicación.',
        remediation: '1. Revise las trazas completas de pila (Stacktrace) del proceso.\n2. Verifique los Manuales Administrativos en HTML.',
        riskLevel: 'Medio (Revisión Sugerida)',
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
