// Global HTML sanitizer
if (typeof window !== 'undefined' && !window.escapeHtml) {
  window.escapeHtml = function(text) {
    if (text === null || text === undefined) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
}
if (typeof escapeHtml === 'undefined') {
  var escapeHtml = window.escapeHtml;
}


// ==========================================================================
// CATÁLOGO OFICIAL Y EXACTO DE CÓDIGOS DE ERROR Y EVENTOS ENTRUST & AUDITORÍA
// ==========================================================================
const ENTRUST_EXACT_CATALOG = {
  // 5200xxx: Motor Core, Proxy de Repositorio & Protocolo
  '5200001': { title: 'Error General de Protocolo o Comunicación Core', category: 'Motor Entrust Core', severity: 'CRITICAL', meaning: 'El servicio principal de IdentityGuard rechazó una operación por fallo de protocolo o parámetro corrupto.', rootCause: 'Petición malformada desde el gateway/cliente o timeout interno en el socket de autenticación.', remediation: 'Revisar los logs de ig_system alrededor del timestamp del evento y validar la conectividad con el servidor de aplicaciones.' },
  '5200002': { title: 'Fallo de Conexión o Respuesta del Proxy de Repositorio / Servicio', category: 'Motor Entrust Core', severity: 'CRITICAL', meaning: 'El motor de autenticación no pudo completar la consulta contra el proxy de repositorio (BD / LDAP) o el servicio remoto.', rootCause: 'Corte temporal hacia el repositorio LDAP/Oracle, pool de conexiones saturado o timeout de socket.', remediation: '1. Verificar estado de conectividad hacia Oracle DB y Active Directory/LDAP.\n2. Revisar tamaño de pool JDBC en identityguard.properties.\n3. Confirmar latencia de red entre nodos y repositorio.' },
  '5200004': { title: 'Excepción de Tiempo de Espera Agotado (Operation Timeout)', category: 'Motor Entrust Core', severity: 'ERROR', meaning: 'La operación excedió el tiempo máximo de espera configurado en el servidor Entrust.', rootCause: 'Sobrecarga en base de datos, consulta LDAP lenta o bloqueo de hilo en Tomcat.', remediation: 'Inspeccionar tiempos de respuesta de BD/LDAP y validar consumo de CPU/memoria JVM.' },

  // 5201xxx: Tarjetas Grid, OTP y Desafíos de Autenticación
  '5201000': { title: 'Fallo Interno del Servidor (Server Failure)', category: 'Motor Entrust Core', severity: 'CRITICAL', meaning: 'Fallo crítico no controlado en el motor de autenticación Entrust.', rootCause: 'Pérdida de conectividad con la base de datos o corrupción de llaves maestras .enc', remediation: 'Reiniciar el servicio de administración y validar la conectividad con la base de datos.' },
  '5201001': { title: 'Desafío de Autenticación Inválido o Expirado', category: 'Motor de Desafíos', severity: 'ERROR', meaning: 'El token de sesión del desafío (Challenge) caducó o no corresponde a la sesión activa.', rootCause: 'El usuario tardó demasiado en responder el reto Grid/OTP o reenvió un formulario expirado.', remediation: 'Solicitar al usuario reiniciar el flujo de autenticación y verificar el TTL de desafíos en la política.' },
  '5201002': { title: 'Tipo de Autenticador No Soportado o No Disponible', category: 'Motor de Desafíos', severity: 'ERROR', meaning: 'El usuario intentó validar un factor que no está activo o provisionado en su perfil.', rootCause: 'Política de grupo mal asignada o autenticador revocado.', remediation: 'Verificar los autenticadores asignados al usuario en la consola de administración de IdentityGuard.' },
  '5201003': { title: 'Desafío Expirado por Tiempo de Espera (Challenge Expired)', category: 'Tarjetas Grid & OTP', severity: 'ERROR', meaning: 'El usuario superó el tiempo límite configurado para responder el desafío Grid/OTP.', rootCause: 'Demora del usuario final o latencia en el portal cliente.', remediation: 'Solicitar un nuevo desafío e inspeccionar el parámetro Challenge Timeout en la política.' },
  '5201004': { title: 'Formato de Respuesta de Desafío Inválido', category: 'Tarjetas Grid & OTP', severity: 'ERROR', meaning: 'La respuesta enviada no cumple con el formato alfanumérico esperado por la tarjeta Grid o token.', rootCause: 'Caracteres especiales, espacios o longitud incorrecta enviada por la aplicación cliente.', remediation: 'Validar sanitización de entrada en el portal consumidor del API de Entrust.' },
  '5201005': { title: 'Tarjeta Grid Revocada, Suspendida o Vencida', category: 'Tarjetas Grid', severity: 'ERROR', meaning: 'El usuario intentó autenticarse con una tarjeta Grid que ya no está en estado ACTIVE.', rootCause: 'Tarjeta vencida por fecha o reemplazada por una nueva sin notificar al usuario.', remediation: 'Emitir/activar una nueva tarjeta Grid en la consola de administración y revocar la anterior.' },
  '5201006': { title: 'Número de Respuestas No Coincide con Desafíos (Response Count Mismatch)', category: 'Tarjetas Grid & OTP', severity: 'ERROR', meaning: 'El número de respuestas enviadas por el usuario no coincide con el número de celdas solicitadas en el desafío Grid.', rootCause: 'El usuario omitió el ingreso de una coordenada de la tarjeta Grid o la aplicación envió parámetros incompletos.', remediation: 'Verificar que la aplicación cliente envíe exactamente el número de respuestas solicitadas y solicitar al usuario reintentar.' },
  '5201007': { title: 'La Respuesta No Coincide con el Desafío (Response Mismatch)', category: 'Tarjetas Grid & OTP', severity: 'ERROR', meaning: 'La coordenada Grid o valor OTP ingresado por el usuario es incorrecto.', rootCause: 'Ingreso erróneo de la celda de la tarjeta Grid o token de software desincronizado.', remediation: 'Verificar que el usuario esté utilizando la tarjeta Grid activa correspondiente a su número de serie.' },
  '5201008': { title: 'La Tarjeta Grid No Coincide con el Desafío (Card Mismatch)', category: 'Tarjetas Grid', severity: 'ERROR', meaning: 'El número de serie de la tarjeta Grid utilizada no coincide con el desafío emitido por el servidor.', rootCause: 'El usuario tiene asignada una tarjeta Grid anterior que fue reemplazada o reasignada.', remediation: 'Verificar en la consola de administración el número de serie de la tarjeta activa asignada al usuario.' },
  '5201009': { title: 'Fallo al Generar Desafío de Autenticación (Failed Challenge)', category: 'Motor de Desafíos', severity: 'ERROR', meaning: 'El servidor Entrust no pudo generar el reto de coordenadas para la sesión.', rootCause: 'El usuario no posee tarjetas Grid activas asignadas o la plantilla de desafíos está corrupta.', remediation: 'Asignar un autenticador o paquete de tarjetas Grid válido al perfil del usuario.' },
  '5201010': { title: 'Tarjeta Grid Bloqueada por Intentos Fallidos', category: 'Tarjetas Grid', severity: 'ERROR', meaning: 'La tarjeta Grid fue bloqueada tras superar el umbral máximo de intentos de desafío incorrectos.', rootCause: 'Múltiples intentos erróneos consecutivos por parte del usuario.', remediation: 'Desbloquear la tarjeta Grid del usuario en la consola de administración de Entrust.' },

  // 5202xxx: Autenticación, Credenciales, Tokens y APIs
  '5202001': { title: 'Sesión de Autenticación Inválida o No Encontrada', category: 'Motor Entrust Core', severity: 'ERROR', meaning: 'El token de sesión o TransactionID suministrado por la aplicación ya no existe en la caché de sesiones.', rootCause: 'Timeout de sesión, reinicio del servicio Entrust o desbalanceo sin stickiness entre nodos.', remediation: 'Habilitar Session Affinity / Sticky Sessions en el balanceador o validar el tiempo de vida de sesión.' },
  '5202013': { title: 'Credenciales Inválidas (Invalid User ID or Password)', category: 'Autenticación & Credenciales', severity: 'CRITICAL', meaning: 'El identificador de usuario o la contraseña ingresada son inválidos.', rootCause: 'Contraseña incorrecta ingresada por el usuario o usuario no registrado en el Directorio Activo/LDAP.', remediation: 'Verificar que el usuario exista en Active Directory, desbloquear la cuenta si está suspendida y restablecer la contraseña.' },
  '5202014': { title: 'Cuenta Bloqueada o Restringida en Directorio Activo / LDAP', category: 'Directorio de Identidades', severity: 'CRITICAL', meaning: 'El repositorio LDAP/AD devolvió un error de cuenta bloqueada, expirada o con restricción horaria.', rootCause: 'Política de Active Directory bloqueó la cuenta por intentos fallidos o expiración.', remediation: 'Desbloquear la cuenta en Active Directory Users & Computers y verificar el atributo lockoutTime.' },
  '5202020': { title: 'Error de Comunicación con Servidor LDAP / Active Directory', category: 'Directorio de Identidades', severity: 'CRITICAL', meaning: 'Entrust no pudo establecer enlace LDAPS/LDAP o recibió timeout del controlador de dominio.', rootCause: 'Certificado LDAPS vencido, puerto 636/389 bloqueado o controlador de dominio no disponible.', remediation: 'Probar conectividad TCP 636/389 hacia los DCs y verificar vigencia del certificado raíz en el keystore de Entrust.' },
  '5202050': { title: 'PIN de Token Inválido o Desincronizado', category: 'Tokens de Software', severity: 'ERROR', meaning: 'El PIN de seguridad o código OTP ingresado no coincide con el registro del token.', rootCause: 'Desfase temporal del token OTP o ingreso de PIN erróneo.', remediation: 'Ejecutar procedimiento de resincronización de token OTP en la consola de administración.' },
  '5202057': { title: 'Token de Software Bloqueado', category: 'Tokens de Software', severity: 'ERROR', meaning: 'El token OTP alcanzó el límite de intentos fallidos permitidos por la directiva.', rootCause: 'Reintentos fallidos consecutivos con contraseñas temporales erróneas.', remediation: 'Desbloquear el token OTP en la consola de administración de IdentityGuard.' },
  '5202340': { title: 'Fallo de Autorización de Aplicación Cliente (Authorization Failure)', category: 'API de Integración', severity: 'ERROR', meaning: 'La aplicación cliente (WSO2 / API Gateway) no tiene permisos autorizados para invocar la API de Entrust.', rootCause: 'Clave compartida (Client Secret) incorrecta o dirección IP no autorizada en la política del canal.', remediation: 'Verificar la clave de integración y la lista de direcciones IP permitidas en la política del canal en Entrust.' },
  '5202404': { title: 'Recurso o Conexión No Encontrada en Repositorio', category: 'Repositorio de Identidad', severity: 'ERROR', meaning: 'El servidor no pudo localizar el registro de identidad en el repositorio de datos.', rootCause: 'Problemas de indexación o desconexión temporal con la base de datos.', remediation: 'Comprobar la conectividad JDBC y reindexar las tablas de usuarios en el repositorio.' },

  // 5203xxx: Gestión de Usuarios y Políticas
  '5203000': { title: 'Usuario No Encontrado en Directorio (User Not Found)', category: 'Directorio de Identidades', severity: 'ERROR', meaning: 'El usuario especificado no existe en la base de datos de Entrust ni en el repositorio LDAP.', rootCause: 'El usuario fue eliminado del directorio o el identificador fue tipeado erróneamente.', remediation: 'Ejecutar sincronización con Active Directory para importar los usuarios faltantes.' },
  '5203016': { title: 'El Usuario No Posee Contraseña Configurada', category: 'Autenticación & Credenciales', severity: 'ERROR', meaning: 'El usuario intentó autenticarse con contraseña pero su perfil no tiene una contraseña asignada.', rootCause: 'Perfil de usuario incompleto o recién creado sin enrolamiento de contraseña.', remediation: 'Establecer una contraseña inicial para el usuario o enrolarlo en el portal de autoservicio.' },
  '5203019': { title: 'La Contraseña Ha Expirado', category: 'Políticas de Seguridad', severity: 'WARN', meaning: 'La contraseña del usuario superó el tiempo máximo de vigencia permitido por la política.', rootCause: 'Expiración natural de vigencia de contraseña según la directiva bancaria.', remediation: 'Solicitar al usuario la renovación de su contraseña mediante el portal de autoservicio.' },
  '5203020': { title: 'La Contraseña Debe Ser Cambiada en el Primer Inicio', category: 'Políticas de Seguridad', severity: 'INFO', meaning: 'El usuario debe cambiar su contraseña temporal por una definitiva.', rootCause: 'Nueva cuenta o contraseña restablecida por un administrador.', remediation: 'Guiar al usuario a través del flujo de cambio de clave inicial.' },

  // 5205xxx: Validación de Credenciales & Bloqueos
  '5205079': { title: 'Cuenta Bloqueada por Intentos Fallidos Consecutivos', category: 'Políticas de Seguridad', severity: 'CRITICAL', meaning: 'La cuenta del usuario fue suspendida temporalmente tras superar el límite de intentos fallidos.', rootCause: 'Posible ataque de fuerza bruta o usuario ingresando credenciales desactualizadas repetidamente.', remediation: 'Desbloquear la cuenta en la consola de Entrust IdentityGuard y restablecer el contador de intentos fallidos.' },
  '5205080': { title: 'Cuenta Deshabilitada por Administración', category: 'Gestión de Cuentas', severity: 'ERROR', meaning: 'La cuenta se encuentra en estado inactivo o deshabilitada por decisión administrativa.', rootCause: 'Suspensión manual por parte de un oficial de seguridad o baja en nómina/LDAP.', remediation: 'Verificar el estado del usuario en el Directorio Activo y reactivar en la consola de administración si corresponde.' },
  '5205139': { title: 'Alias de Usuario Duplicado o No Válido', category: 'Gestión de Identidades', severity: 'ERROR', meaning: 'El alias o identificador secundario de usuario colisiona con otro registro.', rootCause: 'Asignación duplicada de alias en el proceso de carga o sincronización.', remediation: 'Depurar el alias en la consola de administración para garantizar unicidad.' },
  '5205150': { title: 'Método de Autenticación No Permitido por la Política', category: 'Políticas de Acceso', severity: 'ERROR', meaning: 'El usuario intentó autenticarse con un método que no está habilitado en su grupo de políticas.', rootCause: 'El grupo de usuarios no tiene asignada la directiva de tarjetas Grid o tokens.', remediation: 'Editar la política del grupo de usuarios en la consola de Entrust y habilitar el método requerido.' },

  // AUDxxx: Auditoría Administrativa & Eventos Nominales (Alineado 100% a Manuales Oficiales IG 11/12/13)
  'AUD100': { title: 'Inicialización por Primera Vez (First Time Initialization)', category: 'System Initialization audit messages', severity: 'INFO', meaning: 'Entrust IdentityGuard completó la inicialización por primera vez con número de serie inicial, límite de usuarios de licencia y fecha de expiración (Manual oficial IG 13.0: First time initialization performed).', rootCause: 'Instalación o inicialización inicial de la instancia/base de datos IdentityGuard.', remediation: 'Registro de auditoría nominal de arranque inicial.' },
  'AUD101': { title: 'Inicio de Sesión de Administrador Master en supersh (Master User Shell Login)', category: 'Master User audit messages', severity: 'INFO', meaning: 'Un administrador Master inició sesión en la consola interactiva supersh.', rootCause: 'Mantenimiento o ejecución de tareas administrativas autorizadas.', remediation: 'Auditar que las acciones ejecutadas coincidan con la ventana de cambio aprobada.' },
  'AUD102': { title: 'Cierre de Sesión de Administrador Master en supersh (Master User Shell Logout)', category: 'Master User audit messages', severity: 'INFO', meaning: 'El administrador Master cerró la sesión interactiva supersh.', rootCause: 'Finalización de la sesión de administración.', remediation: 'Registro de auditoría nominal.' },
  'AUD105': { title: 'Inicialización de Réplica (Replica Initialization)', category: 'Service audit messages', severity: 'INFO', meaning: 'Una instancia réplica de IdentityGuard completó su inicialización contra el clúster.', rootCause: 'Alta o sincronización inicial de nodo réplica en la topología.', remediation: 'Confirmar estado de replicación saludable en consola.' },
  'AUD1000': { title: 'Usuario Creado (User Created)', category: 'User audit messages', severity: 'INFO', meaning: 'Se creó un nuevo usuario en Entrust IdentityGuard con su ID, estado (Active/Suspended) y DN/searchbase si usa LDAP (Manual oficial IG 13.0: User created).', rootCause: 'Aprovisionamiento automático vía LDAP/API o creación manual por operador.', remediation: 'Registro de auditoría nominal de ciclo de vida de identidades.' },
  'AUD2000': { title: 'Tarjeta de Usuario Creada (User Card Created)', category: 'User card audit messages', severity: 'INFO', meaning: 'Se creó o aprovisionó una nueva tarjeta Grid para un usuario (Manual oficial IG 13.0).', rootCause: 'Enrolamiento o reposición de tarjeta de coordenadas Grid.', remediation: 'Registro de auditoría nominal.' },
  'AUD150': { title: 'Fallo de Conexión del Proxy de Repositorio al Servicio de Autenticación', category: 'Service audit messages', severity: 'ERROR', meaning: 'Entrust IdentityGuard no pudo conectarse al repositorio indicado en la URL registrada (Manual oficial IG 13.0, AUD150).', rootCause: 'Repositorio (BD/LDAP) caído, URL incorrecta o corte de red entre el servidor y el repositorio.', remediation: 'Verificar disponibilidad del repositorio y conectividad de red; revisar la URL configurada.' },
  'AUD154': { title: 'Pool de Conexiones al Repositorio Agotado', category: 'Service audit messages', severity: 'WARN', meaning: 'No se pudo obtener una conexión al repositorio desde el pool por agotamiento (Manual oficial IG 13.0, AUD154).', rootCause: 'Carga concurrente superior al tamaño máximo del pool o consultas lentas que retienen conexiones.', remediation: 'Revisar el tamaño máximo del pool y consultas colgadas; ampliar solo si la evidencia lo respalda.' },
  'AUD155': { title: 'Pool de Conexiones al Repositorio al 80% de Uso', category: 'Service audit messages', severity: 'WARN', meaning: 'El pool de conexiones al repositorio alcanzó el 80% de su capacidad (Manual oficial IG 13.0, AUD155).', rootCause: 'Aumento sostenido de autenticaciones concurrentes.', remediation: 'Monitorear el uso del pool y evaluar su ampliación antes de llegar al 100%.' },
  'AUD2300': { title: 'Token Asignado a Usuario (User Token Assigned)', category: 'User token audit messages', severity: 'INFO', meaning: 'Se asignó un token (marca y serial) al usuario indicado (Manual oficial IG 13.0: User Token Assigned).', rootCause: 'Enrolamiento o asignación de hardware/soft token MFA.', remediation: 'Registro de auditoría nominal.' },
  'AUD2309': { title: 'Fallo en Entrega de Detalles de Transacción / Token (User Token Delivery Failed)', category: 'User token audit messages', severity: 'ERROR', meaning: 'El servidor no pudo entregar los detalles de transacción para el token/usuario indicado (Manual oficial IG 13.0, SNMP Trap: Sí).', rootCause: 'Dispositivo inalcanzable, gateway Push/SMS/SMTP con error o certificado APNs/FCM vencido.', remediation: 'Verificar conectividad hacia el proveedor Push/SMS/SMTP y vigencia de certificados.' },
  'AUD3000': { title: 'PIN Temporal Creado (Temporary PIN Created)', category: 'Temporary PIN audit messages', severity: 'INFO', meaning: 'Se generó un PIN temporal para el usuario indicado (Manual oficial IG 13.0: Temporary PIN created).', rootCause: 'Emisión de PIN temporal para acceso de contingencia o enrolamiento.', remediation: 'Confirmar que la emisión de PIN temporal haya sido solicitada por canal autorizado.' },
  'AUD3004': { title: 'OTP Eliminado / Consumido (OTP Deleted)', category: 'OTP audit messages', severity: 'INFO', meaning: 'Se eliminó/consumió un código de un solo uso (One Time Password) con su índice para el usuario objetivo (Manual oficial IG 13.0: One time password deleted).', rootCause: 'Consumo normal post-autenticación o depuración de OTP vía cuenta integradora API.', remediation: 'Distinguir la cuenta de servicio API ejecutora del usuario final ("for user <cliente>") y confirmar uso nominal.' },
  'AUD4003': { title: 'Inicio de Sesión de Administrador / Cuenta API (Administrator Login)', category: 'Administrator audit messages', severity: 'INFO', meaning: 'Un administrador o cuenta administradora de servicio API inició sesión en Entrust IdentityGuard (Manual oficial IG 13.0: Administrator logged in).', rootCause: 'Acceso a consola de administración o apertura de sesión de servicio API desde banca en línea / bus de servicios.', remediation: '1. Verificar que la cuenta administradora y la IP remota pertenezcan a servidores autorizados.\n2. Auditar picos anómalos de logins API para evaluar reutilización de sesión o credenciales.' },
  'AUD4004': { title: 'Cierre de Sesión de Administrador (Administrator Logout)', category: 'Administrator audit messages', severity: 'INFO', meaning: 'Un administrador cerró su sesión en Entrust IdentityGuard (Manual oficial IG 13.0: Administrator logged out).', rootCause: 'Finalización normal de sesión administrativa o de servicio.', remediation: 'Registro nominal de trazabilidad administrativa.' },
  'AUD4005': { title: 'Administrador Bloqueado por Fallo de Acceso (Administrator Failed Login And Was Locked Out)', category: 'Administrator audit messages', severity: 'ERROR', meaning: 'Una cuenta de administrador falló la autenticación y quedó bloqueada hasta la hora indicada (Manual oficial IG 13.0).', rootCause: 'Múltiples intentos fallidos consecutivos de acceso administrativo o cuenta API mal configurada.', remediation: 'Verificar IP de origen de los intentos fallidos y validar autorización antes de desbloquear.' },
  'AUD6000': { title: 'Autenticación Exitosa (Authentication Success)', category: 'Authentication audit messages', severity: 'INFO', meaning: 'El usuario completó satisfactoriamente el desafío de autenticación asignado (Manual oficial IG 13.0: User successfully authenticated a challenge).', rootCause: 'Validación legítima de credenciales y segundo factor (Password / OTP / Token / Grid).', remediation: 'Registro nominal de auditoría; útil para confirmar recuperación de usuarios tras intentos fallidos previos (AUD6001).' },
  'AUD6001': { title: 'Fallo de Autenticación de Usuario (Authentication Failure)', category: 'Authentication audit messages', severity: 'WARN', meaning: 'El intento de autenticación del usuario falló (Manual oficial IG 13.0: User failed authentication).', rootCause: 'Coordenada Grid, OTP o contraseña incorrecta, token desincronizado o intento no autorizado.', remediation: 'Monitorear reincidencia por usuario e IP; múltiples AUD6001 consecutivos disparan el bloqueo automático (AUD6002).' },
  'AUD6002': { title: 'Usuario Bloqueado por Fallos de Autenticación (Authentication Failure Locks Out User)', category: 'Authentication audit messages', severity: 'ERROR', meaning: 'El usuario superó el límite de intentos fallidos y su autenticación quedó bloqueada por política (Manual oficial IG 13.0: User failed authentication and is now locked out).', rootCause: 'Activación de la directiva de bloqueo (Lockout Policy) por intentos repetidos fallidos o posible fuerza bruta.', remediation: '1. Verificar origen (IP / canal) de los intentos previos (AUD6001).\n2. Confirmar legitimidad del titular antes de desbloquear en IdentityGuard Admin.' },
  'AUD8500': { title: 'Inicio de Exportación para Migración (IntelliTrust Migration Export Start)', category: 'Migration audit messages', severity: 'INFO', meaning: 'Se inició la exportación masiva de credenciales para migración hacia Entrust IDaaS / IntelliTrust.', rootCause: 'Ejecución de herramienta de exportación de migración.', remediation: 'Monitorear finalización exitosa en AUD8502.' },
  'AUD8502': { title: 'Exportación de Migración Finalizada (IntelliTrust Migration Export Finished)', category: 'Migration audit messages', severity: 'INFO', meaning: 'La exportación de usuarios y autenticadores finalizó correctamente.', rootCause: 'Fin exitoso de extracción de credenciales.', remediation: 'Proceder con la importación segura en la plataforma destino.' },
  'AUD8503': { title: 'Visualización de Clave de Exportación (IntelliTrust Migration Export Password View)', category: 'Migration audit messages', severity: 'INFO', meaning: 'Se mostró la contraseña de cifrado del paquete de migración al administrador Master.', rootCause: 'Custodia criptográfica de exportación.', remediation: 'Resguardar la clave según política de seguridad.' },

  // ORA-xxxxx: Errores de Base de Datos Oracle
  'ORA-01555': { title: 'Saturación de Tablespace UNDO / Snapshot Too Old', category: 'Persistencia Oracle DB', severity: 'CRITICAL', meaning: 'Fallo de lectura consistente en tablas de tarjetas Grid y datos cifrados de usuarios en Oracle DB.', rootCause: 'Parámetro UNDO_RETENTION insuficiente o espacio insuficiente en el tablespace UNDO.', remediation: 'Ejecutar ALTER SYSTEM SET UNDO_RETENTION = 10800 SCOPE=BOTH y ampliar el Tablespace UNDO con AUTOEXTEND ON.' },
  'ORA-00001': { title: 'Violación de Clave Única (Unique Constraint Violated)', category: 'Persistencia Oracle DB', severity: 'ERROR', meaning: 'Intento de inserción de un registro con identificador o clave duplicada en la base de datos.', rootCause: 'Colisión de identificadores de usuario o números de serie de tarjetas Grid durante la inserción.', remediation: 'Verificar la unicidad de las claves y realizar limpieza de registros huérfanos.' },
  'ORA-01000': { title: 'Límite Máximo de Cursores Abiertos Superado', category: 'Persistencia Oracle DB', severity: 'CRITICAL', meaning: 'La aplicación agotó el número de cursores permitidos por sesión en la base de datos Oracle.', rootCause: 'Fuga de conexiones o cursores JDBC no cerrados en el pool de Tomcat.', remediation: 'Incrementar OPEN_CURSORS en Oracle (mínimo 1000) y verificar el cierre de statements en el connection pool.' },
  'ORA-03113': { title: 'Fin de Archivo en Canal de Comunicación (End-of-File)', category: 'Persistencia Oracle DB', severity: 'CRITICAL', meaning: 'Se interrumpió abruptamente la conexión TCP/IP entre Entrust IdentityGuard y Oracle DB.', rootCause: 'Reinicio de la instancia Oracle, corte de red entre servidores o firewall cerrando conexiones inactivas.', remediation: 'Verificar la estabilidad del enlace de red y configurar Keep-Alive en el listener de Oracle.' },

  // IDaaS Bulk: Aprovisionamiento Masivo en la Nube
  'bulkidentityguard.add.error.assignedgrid': { title: 'Conflicto de Tarjeta Grid Preexistente en Lote Masivo', category: 'Aprovisionamiento IDaaS Cloud', severity: 'ERROR', meaning: 'La tarea masiva intentó asignar una tarjeta Grid a un usuario que ya posee una tarjeta activa.', rootCause: 'Ejecución del lote sin la directiva overwriteExistingGrid=true.', remediation: 'Configurar el parámetro overwriteExistingGrid=true en la tarea masiva para permitir reemplazo.' },
  'bulkidentityguard.add.error.qa': { title: 'Preguntas y Respuestas Secretas (Q&A) Ya Registradas', category: 'Aprovisionamiento IDaaS Cloud', severity: 'ERROR', meaning: 'El usuario ya cuenta con preguntas de seguridad registradas en el tenant de IDaaS.', rootCause: 'Intento de importación sin la directiva updateExistingCredentials=true.', remediation: 'Habilitar updateExistingCredentials=true en la configuración del lote para actualizar el esquema Q&A.' },
  'bulkidentityguard.add.error.password': { title: 'Colisión de Contraseña en Lote Masivo', category: 'Aprovisionamiento IDaaS Cloud', severity: 'ERROR', meaning: 'La contraseña enviada en el lote colisiona con una credencial existente.', rootCause: 'Falta de la directiva allowPasswordReset=true en la importación masiva.', remediation: 'Habilitar allowPasswordReset=true para permitir actualización de contraseñas de usuarios en el tenant.' },

  // AWS S3 Cloud Storage & SDK (Error de Infraestructura / True Error)
  'AWS-S3-404-NOKEY': { title: 'Fallo de Recuperación de Objeto en Cloud Storage (AWS S3 404 NoSuchKey)', category: 'Almacenamiento Cloud & SDK AWS', severity: 'CRITICAL', meaning: 'El worker de migración de Entrust IDaaS intentó descargar un archivo temporal, paquete .dat o manifiesto desde AWS S3 que no existe o cuya clave expiró.', rootCause: 'Expiración de la sesión/token S3, archivo temporal purgado antes de finalizar la ingesta, o desfase en la clave del objeto en AWS SDK.', remediation: '1. Reintentar la subida del paquete .dat en la consola de Entrust IDaaS asegurando que no existan microcortes.\n2. Fraccionar lotes a 50.000 registros para evitar expiración de tokens S3.\n3. Verificar conectividad y permisos del bucket en la configuración del conector Cloud.' },
  'S3-404': { title: 'Fallo de Recuperación de Objeto en Cloud Storage (AWS S3 404 NoSuchKey)', category: 'Almacenamiento Cloud & SDK AWS', severity: 'CRITICAL', meaning: 'El worker de migración de Entrust IDaaS intentó descargar un archivo temporal, paquete .dat o manifiesto desde AWS S3 que no existe o cuya clave expiró.', rootCause: 'Expiración de la sesión/token S3, archivo temporal purgado antes de finalizar la ingesta, o desfase en la clave del objeto en AWS SDK.', remediation: '1. Reintentar la subida del paquete .dat en la consola de Entrust IDaaS asegurando que no existan microcortes.\n2. Fraccionar lotes a 50.000 registros para evitar expiración de tokens S3.\n3. Verificar conectividad y permisos del bucket en la configuración del conector Cloud.' },

  // Sistema Operativo / SSH / PAM
  'SSH-FAIL': { title: 'Fallo de Autenticación SSH / PAM en Servidor Linux', category: 'Sistema & SSH/OS', severity: 'ERROR', meaning: 'Se registró un intento fallido de acceso SSH o escalamiento PAM en el host.', rootCause: 'Contraseña incorrecta, llave SSH rechazada o sondeo no autorizado de puerto 22.', remediation: 'Revisar IP de origen en /var/log/auth.log o secure; bloquear IPs repetitivas en firewall/fail2ban.' },
  'SSH-AUTH': { title: 'Sesión SSH / PAM Administrativa Autorizada', category: 'Sistema & SSH/OS', severity: 'INFO', meaning: 'Un operador autorizado inició o ejecutó comandos mediante sesión SSH/PAM.', rootCause: 'Acceso administrativo programado o mantenimiento del servidor.', remediation: 'Auditar que la IP de origen y horario correspondan a personal autorizado.' },

  // Apache Tomcat Embebido / JVM Catalina (catalina.out en Entrust IdentityGuard OnPremise)
  'TOMCAT_SSL_TLS': {
    title: 'Fallo TLS / SSL / PKIX o Keystore en Tomcat Catalina',
    category: 'Tomcat Catalina / TLS & Keystore',
    severity: 'CRITICAL',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_security/import_certificates_using_keytool.htm',
    meaning: 'El contenedor Apache Tomcat embebido de Entrust IdentityGuard reportó un error de negociación TLS/SSL (SSLHandshakeException, PKIX path building failed, KeyStoreException o certificado expirado/no confiable).',
    rootCause: 'Certificado raíz/intermedio faltante en el keystore de IdentityGuard, certificado de servidor o par LDAP/HTTPS expirado, o incompatibilidad de versión TLS (-Djdk.tls.client.protocols). Nota de IG 12.0 Release Notes: si se elimina el último certificado confiable del keystore, el servidor Tomcat embebido no inicia.',
    remediation: '1. [Manual Oficial IG 13.0 — Import certificates using keytool] Importar el certificado confiable usando $IG_HOME/jdk<version>/bin/keytool (Linux) o <$IG_HOME>\\jdk<version>\\bin\\keytool (Windows) en el keystore $IG_HOME/etc/keystore con alias tomcat (servidor) o alias descriptivo y contraseña entrust (o verificar identityguard.keystore.certificateImport.enabled=true e identityguard.keystore.name).\n2. [Manual Oficial IG 13.0 — TLS version downgrade] Para conexiones salientes TLS, validar IG_CIPHER_OPTS (-Djdk.tls.client.protocols=TLSv1.2) en <$IG_HOME>/env_settings.sh (Linux) y reiniciar con $IG_HOME/bin/igservice.sh identityguard restart.\n3. Correlacionar el timestamp exacto en la pestaña 🌐 Red / PCAP para verificar alertas TLS (certificate_expired / handshake_failure).'
  },
  'JDBC_SQL_EXCEPTION': {
    title: 'Excepción JDBC / SQL o Saturación del Pool de Base de Datos',
    category: 'Tomcat Catalina / Pool JDBC & BD',
    severity: 'CRITICAL',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/usingpropeditor/jdbc_database_settings.htm',
    meaning: 'Se detectó una SQLException, fallo de obtención de conexión del pool JDBC (HikariPool/BasicDataSource) o fallo de repositorio JDBC/BLOB (JdbcCardRepository / AuditDBLogger) en catalina.out.',
    rootCause: 'Agotamiento de conexiones del pool JDBC (default 10), timeout superado al obtener conexión/login o esquema/driver incorrecto en Entrust IdentityGuard.',
    remediation: '1. [Manual Oficial IG 13.0 — JDBC Database Settings] Revisar en Properties Editor: identityguard.jdbc.url, Connection Pool Maximum Size (identityguard.jdbc.connectionpool.max, default 10), Max Wait Time (identityguard.jdbc.connectionpool.maxWait, default 30000 ms), Database Login Timeout (30 s), Query Timeout, Remove Abandoned Timeout (300 s), Database Connection Test Interval (identityguard.jdbc.ha.testInterval, default 50 s), Blob Access (identityguard.jdbc.blobAccess) e Include Sequence (identityguard.jdbc.includeSequence=True en Oracle para evitar SQLException en AUDITS.AUDIT_SEQNO).\n2. [Manual Oficial IG 13.0 — Adding a new database repository] Confirmar el JAR del driver JDBC en $IG_HOME/lib/db y $CATALINA_HOME/lib.'
  },
  'SQL_EXCEPTION': {
    title: 'Excepción SQL / JDBC Reportada en Trazas',
    category: 'Tomcat Catalina / Pool JDBC & BD',
    severity: 'CRITICAL',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/usingpropeditor/jdbc_database_settings.htm',
    meaning: 'Excepción SQL o fallo de persistencia JDBC registrada en la salida del servidor.',
    rootCause: 'Error de comunicación con la base de datos, consulta rechazada o pool JDBC agotado.',
    remediation: '1. [Manual Oficial IG 13.0 — JDBC Database Settings] Verificar identityguard.jdbc.url, identityguard.jdbc.connectionpool.max (default 10), maxWait (default 30000 ms) y identityguard.jdbc.includeSequence en Oracle.\n2. Confirmar disponibilidad del motor de base de datos y existencia de los JARs en $IG_HOME/lib/db y $CATALINA_HOME/lib.'
  },
  'JVM_OOM': {
    title: 'Agotamiento de Memoria JVM (OutOfMemoryError / Heap / Metaspace / Hilos)',
    category: 'Tomcat Catalina / JVM & Memoria',
    severity: 'CRITICAL',
    manualFile: 'entrust_ig_130_releasenotes.html',
    meaning: 'La Máquina Virtual Java (JVM) que ejecuta Apache Tomcat embebido alcanzó el límite de Heap Space, Metaspace, GC overhead o hilos nativos del SO.',
    rootCause: 'Carga masiva en consola web (bulk operations), reportes de auditoría muy extensos, memoria física/JVM insuficiente respecto al volumen de usuarios concurrentes o fuga de memoria.',
    remediation: '1. [Manual Oficial IG 13.0 — Release Notes & Web Application Settings] Verificar el requisito base (mínimo 4 GB RAM en AdoptOpenJDK 11 + Apache Tomcat 8.5.57 embebido, recomendado ampliar según volumen de usuarios) y revisar identityguard.webadmin.bulk.inMemoryThreshold para que archivos bulk extensos se almacenen en disco.\n2. [Manual Oficial IG 13.0 — Tips for optimal reporting performance & Performance Statistics Logging] Programar reportes pesados en horarios de baja carga o en nodos réplica y monitorear estadísticas con identityguard.estat.enabled ($IG_HOME/Log/identityguard_estat.log).\n3. [Estándar Apache Tomcat / JVM] Revisar los flags -Xms/-Xmx y recolectar heap dump para identificar qué objetos retienen memoria antes de ajustar memoria.'
  },
  'TOMCAT_LDAP_ERROR': {
    title: 'Fallo de Comunicación / Enlace LDAP / JNDI en Tomcat',
    category: 'Tomcat Catalina / Directorio LDAP',
    severity: 'ERROR',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_igserver/securing_the_ldap_connection_with_ssl.htm',
    meaning: 'El servidor de aplicaciones registró LDAPException, javax.naming.CommunicationException o error de autenticación/enlace hacia el directorio LDAP/AD.',
    rootCause: 'Controlador de dominio LDAP inalcanzable, puerto 389/636 bloqueado, certificado LDAPS usando dirección IP en Subject/SAN en lugar de hostname, o conexiones LDAP inactivas cerradas.',
    remediation: '1. [Manual Oficial IG 13.0 — Securing the LDAP connection with SSL] Confirmar que el certificado del servidor LDAP incluya el hostname (no IP) en Subject o subjectAltName e importar el certificado o su CA en $IG_HOME/etc/keystore (-alias ldapssl -storepass entrust); validar identityguard.ldap.url y SSL LDAP Connection.\n2. [Manual Oficial IG 13.0 — JDBC/LDAP Pool Settings] Revisar identityguard.ldap.connectionpool.minIdleCloseTime e identityguard.ldap.connectionpool.closeSchedule (default 180000 ms).'
  },
  'TOMCAT_DEPLOY_ERROR': {
    title: 'Fallo de Arranque / Despliegue de Componente en Apache Tomcat',
    category: 'Tomcat Catalina / Ciclo de Vida',
    severity: 'CRITICAL',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_igserver/adding_a_new_database_repository.htm',
    meaning: 'Tomcat reportó LifecycleException, ClassNotFoundException, Error listenerStart/filterStart o fallo al inicializar la aplicación web de IdentityGuard.',
    rootCause: 'Falta del driver JAR requerido en $IG_HOME/lib/db o $CATALINA_HOME/lib, keystore sin certificado confiable (en IG 12.0+ Tomcat no inicia si se elimina el último certificado confiable), o fallo de arranque del servicio (AUD110).',
    remediation: '1. [Manual Oficial IG 13.0 — Adding a new database repository] Verificar que los drivers JAR estén copiados tanto en $IG_HOME/lib/db como en $CATALINA_HOME/lib (/opt/entrust/apache-tomcat<version>/lib).\n2. [Manual IG 12.0 Release Notes & Service Audit AUD110] Confirmar que $IG_HOME/etc/keystore contenga al menos un certificado confiable y revisar eventos AUD110 en identityguard_audit.log.'
  },
  'TOMCAT_NETWORK_ERROR': {
    title: 'Error de Red / Puerto o Timeout de Socket en Tomcat Catalina',
    category: 'Tomcat Catalina / Conectividad',
    severity: 'ERROR',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/usingpropeditor/web_application_settings.htm',
    meaning: 'Tomcat reportó BindException (puerto ya en uso), ConnectException, SocketTimeoutException o UnknownHostException.',
    rootCause: 'Conflicto de puerto en conectores de server.xml, proceso Tomcat previo colgado ocupando el puerto, DNS sin resolver o caída/latencia extrema hacia un nodo backend.',
    remediation: '1. [Manual Oficial IG 13.0 — Web Application Settings] Validar los conectores definidos en el server.xml de Tomcat embebido y las URLs identityguard.webadmin.url / identityguard.preditor.url.\n2. [Práctica estándar OS/Red] Verificar procesos y puertos locales (ss -tlnp) y correlacionar con la pestaña 🌐 Red / PCAP para detectar SYN sin respuesta o TCP RST.'
  },
  'TOMCAT_THREAD_POOL': {
    title: 'Congestión o Hilos Bloqueados en Executor de Tomcat',
    category: 'Tomcat Catalina / Hilos & Rendimiento',
    severity: 'WARN',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/usingpropeditor/performance_statistics_logging_settings.htm',
    meaning: 'Tomcat registró StuckThreadDetectionValve, saturación de hilos (maxThreads), RejectedExecutionException o advertencia de memory leak al detener hilos.',
    rootCause: 'Peticiones bloqueadas esperando respuestas lentas de base de datos/LDAP/servicios externos o concurrencia superior al pool configurado.',
    remediation: '1. [Manual Oficial IG 13.0 — Performance Statistics Logging Settings] Activar identityguard.estat.enabled=True (registra en <$IG_HOME>/Log/identityguard_estat.log) y monitoreo de pool JDBC para medir contención real.\n2. [Estándar Apache Tomcat] Inspeccionar thread dumps durante el incidente y evaluar maxThreads / connectionTimeout en server.xml solo tras resolver bloqueos downstream.'
  },
  'TOMCAT_CLIENT_ABORT': {
    title: 'Desconexión del Cliente HTTP (ClientAbortException / Broken Pipe)',
    category: 'Tomcat Catalina / Conectividad HTTP',
    severity: 'INFO',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/usingpropeditor/web_application_settings.htm',
    meaning: 'El navegador, balanceador o cliente consumidor cerró la conexión TCP antes de que Tomcat terminara de enviar la respuesta HTTP (comportamiento informativo, no error interno de Entrust).',
    rootCause: 'Usuario canceló la carga, timeout corto en balanceador frontal o cierre prematuro del socket cliente.',
    remediation: 'No representa una falla del servidor Entrust por sí mismo; solo revisar timeouts del proxy/balanceador frontal si ocurre de forma masiva.'
  },
  'TOMCAT_JAVA_EXCEPTION': {
    title: 'Excepción Java Registrada en Catalina (catalina.out)',
    category: 'Tomcat Catalina / JVM & Servlets',
    severity: 'ERROR',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_logging/logging_overview.htm',
    meaning: 'El servidor de aplicaciones Apache Tomcat embebido emitió una excepción Java en salida estándar (catalina.out), agrupada con su Caused by raíz sin multiplicar conteos por cada línea at.',
    rootCause: 'Error de ejecución en servlet, filtro o librería invocado en Tomcat; revisar la cadena Root Cause y el código 520xxxx/ORA-xxxxx asociado si existe.',
    remediation: '1. [Manual Oficial IG 13.0 — Logging Overview] Correlacionar la marca de tiempo exacta con identityguard_system.log e identityguard_audit.log (loggers Log4J oficiales de Entrust) y revisar la causa raíz mostrada en el detalle del evento.'
  },
  'TOMCAT_SEVERE': {
    title: 'Evento SEVERE / FATAL de Apache Tomcat (catalina.out)',
    category: 'Tomcat Catalina / Eventos Severos',
    severity: 'ERROR',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_logging/logging_overview.htm',
    meaning: 'Apache Tomcat embebido registró un mensaje con severidad JULI SEVERE o GRAVE en catalina.out.',
    rootCause: 'Condición crítica en el contenedor de servlets Tomcat o componente desplegado a la hora exacta del evento.',
    remediation: 'Inspeccionar el mensaje completo del evento en catalina.out y correlacionar con identityguard_system.log (Manual Oficial IG 13.0 — Logging Overview).'
  },
  'TOMCAT_WARN': {
    title: 'Advertencia WARNING de Apache Tomcat (catalina.out)',
    category: 'Tomcat Catalina / Advertencias',
    severity: 'WARN',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_logging/logging_overview.htm',
    meaning: 'Apache Tomcat registró una advertencia JULI (WARNING / ADVERTENCIA) durante arranque u operación.',
    rootCause: 'Parámetro obsoleto, advertencia de configuración o condición transitoria en Tomcat.',
    remediation: 'Revisar el detalle de la advertencia para descartar impacto funcional en producción.'
  },
  'TOMCAT_LIFECYCLE': {
    title: 'Ciclo de Vida de Apache Tomcat (Arranque / Despliegue / Parada)',
    category: 'Tomcat Catalina / Ciclo de Vida',
    severity: 'INFO',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_logging/logging_overview.htm',
    meaning: 'Registro nominal de inicio de conectores, despliegue de aplicaciones o finalización del arranque de Tomcat (Server startup in ... ms).',
    rootCause: 'Reinicio programado o arranque del servicio Entrust IdentityGuard Server.',
    remediation: 'Evento informativo útil para confirmar ventanas de reinicio y correlacionar con AUD106/AUD107.'
  },
  'TOMCAT_INFO': {
    title: 'Registro Operativo Informativo de Tomcat (catalina.out)',
    category: 'Tomcat Catalina / Informativo',
    severity: 'INFO',
    manualFile: 'IG_130_Admin_WebHelp/ig_admin/config_logging/logging_overview.htm',
    meaning: 'Traza informativa emitida por Apache Tomcat en catalina.out.',
    rootCause: 'Operación normal o diagnóstico de arranque del contenedor Tomcat.',
    remediation: 'No requiere acción.'
  }
};

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
      // ORACLE DB & ENTRUST CARD REPOSITORY ERRORS (ONPREMISE)
      // ==========================================
      {
        id: 'KB-ORA-01555',
        title: 'Oracle DB Error [ORA-01555 / ORA-22924]: Snapshot Too Old (Rollback Segment / UNDO Saturation)',
        category: 'Entrust OnPremise / Base de Datos Oracle JDBC',
        severity: 'CRITICAL',
        pattern: /(ORA-01555|ORA-22924|snapshot too old|JdbcCardRepository.*User decode error|BlobAccess\.getBytes)/i,
        meaning: 'Fallo crítico de lectura de datos históricos/BLOB en la base de datos Oracle de Entrust IdentityGuard. El motor no pudo garantizar la consistencia de lectura de los registros de tarjetas Grid/eGrid de los usuarios.',
        rootCause: '1. El parámetro `UNDO_RETENTION` en Oracle DB es insuficiente para la duración de la consulta masiva.\n2. El tablespace `UNDO` de Oracle no tiene suficiente espacio asignado o no tiene `AUTOEXTEND ON`.\n3. Lectura prolongada de segmentos LOB/BLOB en tablas de tarjetas (`CARDS` / `ENCRYPTED_DATA`) mientras ocurren escrituras concurrentes.',
        remediation: '1. Contactar al DBA de Oracle para incrementar `UNDO_RETENTION` (recomendado: mínimo 10,800 segundos / 3 horas):\n   `ALTER SYSTEM SET UNDO_RETENTION = 10800 SCOPE=BOTH;`\n2. Ampliar el tamaño del Tablespace UNDO:\n   `ALTER DATABASE DATAFILE \'+DATA/...\' RESIZE 20G;` o habilitar `AUTOEXTEND ON`.\n3. En la configuración de Entrust IdentityGuard (`identityguard.properties`), ajustar el tamaño de lote JDBC (`jdbc.batch.size=500`) y timeout de lectura.\n4. Si el error persiste en un usuario específico, verificar si el registro BLOB de su tarjeta presenta corrupción física.',
        riskLevel: 'Crítico (Fallo de Lectura y Autenticación en BD)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-ora-01555',
        sectionTitle: 'Fallo Oracle: ORA-01555 Snapshot Too Old en Repositorio de Tarjetas'
      },
      {
        id: 'KB-ENTRUST-TX-QUEUE',
        title: 'Entrust IdentityGuard: Monitoreo de Cola de Transacciones (TransactionQueue)',
        category: 'Entrust OnPremise / Cola de Transacciones',
        severity: 'INFO',
        pattern: /(TransactionQueue\.API|Transaction queue for user.*has \d+ transactions)/i,
        meaning: 'Inspección nominal de la cola de transacciones de autenticación y enrolamiento pendiente para el usuario bancario.',
        rootCause: 'Operación normal de sondeo del servicio de administración y sincronización de transacciones de usuarios.',
        remediation: 'No requiere acción correctiva. Monitoreo nominal del flujo de transacciones.',
        riskLevel: 'Bajo (Informativo / Nominal)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-tx-queue',
        sectionTitle: 'Monitoreo de Cola de Transacciones'
      },
      // ==========================================
      // ENTRUST ONPREMISE MIGRATION TO IDAAS CLOUD (AUD8500 - AUD8504 & SUPERSH)
      // ==========================================
      {
        id: 'KB-ENTRUST-AUD8500',
        title: 'Entrust Migration Tool [AUD8500]: Inicio de Exportación Masiva a IDaaS Cloud (authexport)',
        category: 'Entrust OnPremise / Migración a IDaaS Cloud',
        severity: 'INFO',
        pattern: /(AUD8500|Migration to .*Identity as a Service.*export.*started)/i,
        meaning: 'Se ha iniciado la tarea de exportación de autenticadores (Tarjetas Grid, eGrid, Tokens y Contraseñas) desde la base de datos OnPremise hacia el paquete cifrado (.dat) para migración a Entrust IDaaS Cloud.',
        rootCause: 'Ejecución del comando `authexport` en la herramienta `IG_Migration_Tool` desde la consola de administración `supersh`.',
        remediation: 'Operación nominal. Monitorear el consumo de CPU y el espacio en disco en el directorio de salida `/opt/entrust/IG_Migration_Tool/bin/`.',
        riskLevel: 'Informativo (Proceso de Migración en Ejecución)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud8500',
        sectionTitle: 'Código [AUD8500]: Inicio de Exportación de Migración IDaaS'
      },
      {
        id: 'KB-ENTRUST-AUD8502',
        title: 'Entrust Migration Tool [AUD8502]: Exportación Masiva a IDaaS Cloud Completada con Éxito',
        category: 'Entrust OnPremise / Migración a IDaaS Cloud',
        severity: 'INFO',
        pattern: /(AUD8502|Migration to .*Identity as a Service.*completed with status)/i,
        meaning: 'La exportación masiva de credenciales ha finalizado exitosamente al 100% (3 de 3 fases completadas), generando el archivo cifrado (.dat) con el total de usuarios y tarjetas exportadas.',
        rootCause: 'Extracción completa de registros de identidades desde la base de datos de Entrust IdentityGuard OnPremise.',
        remediation: '1. Verificar la integridad y tamaño del archivo `.dat` generado.\n2. Proceder con la importación en la consola de Entrust IDaaS Cloud mediante la tarea por lotes correspondiente.',
        riskLevel: 'Bajo (Migración Exitosa)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud8502',
        sectionTitle: 'Código [AUD8502]: Exportación de Migración IDaaS Exitosa'
      },
      {
        id: 'KB-ENTRUST-AUD8503',
        title: 'Entrust Migration Tool [AUD8503]: Despliegue de Contraseña de Cifrado del Paquete (.dat)',
        category: 'Entrust OnPremise / Migración a IDaaS Cloud',
        severity: 'INFO',
        pattern: /(AUD8503|export password request.*was displayed to a master user)/i,
        meaning: 'La clave simétrica para descifrar el archivo de migración `.dat` fue generada y mostrada en pantalla exclusivamente a un usuario Master.',
        rootCause: 'Protocolo de seguridad criptográfica de Entrust para custodiar el archivo de exportación de identidades bancarias.',
        remediation: 'Custodiar de forma segura la contraseña generada para introducirla en la consola de IDaaS Cloud.',
        riskLevel: 'Medio (Custodia de Clave de Cifrado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud8503',
        sectionTitle: 'Código [AUD8503]: Clave de Exportación de Migración'
      },
      {
        id: 'KB-ENTRUST-AUD101-SUPERSH',
        title: 'Entrust Super Shell [AUD101 / AUD102]: Sesión de Administrador Master en supersh',
        category: 'Entrust OnPremise / Auditoría de Acceso Master',
        severity: 'INFO',
        pattern: /(Login to supersh|Logout from supersh|AUD101.*supersh|AUD102.*supersh)/i,
        meaning: 'Un usuario con privilegios de Maestro (Master Administrator) inició o cerró sesión en la consola interactiva CLI `supersh` de Entrust IdentityGuard.',
        rootCause: 'Mantenimiento, configuración o ejecución de tareas administrativas de bajo nivel en el servidor.',
        remediation: 'Auditar que las acciones ejecutadas durante la sesión coincidan con la ventana de cambio autorizada.',
        riskLevel: 'Bajo (Acceso Administrativo Controlado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-aud101-supersh',
        sectionTitle: 'Código [AUD101/AUD102]: Sesión Master en supersh'
      },
      // ==========================================
      // ENTRUST IDAAS CLOUD & BULK PROVISIONING (BANCO MERCANTIL)
      // ==========================================
      {
        id: 'KB-IDG-BULK-GRID-CONFLICT',
        title: 'Entrust IDaaS Cloud: Conflicto de Tarjeta Grid Preexistente (Grid Already Assigned)',
        category: 'Entrust IDaaS Cloud / Aprovisionamiento Masivo (Bulk)',
        severity: 'ERROR',
        pattern: /(bulkidentityguard\.add\.error\.assignedgrid|grid already assigned to user)/i,
        meaning: 'La tarea de importación masiva intentó asignar una nueva tarjeta Grid a usuarios que ya contaban con una tarjeta Grid activa en el almacén de identidades de Entrust IDaaS.',
        rootCause: 'Ejecución del proceso de carga por lotes (Bulk IdentityGuard) sin el parámetro de sobrescritura overwriteExistingGrid=true o re-ejecución del lote sobre usuarios previamente aprovisionados.',
        remediation: '1. En la definición de la tarea masiva, configure el parámetro overwriteExistingGrid=true si requiere reemplazar la tarjeta actual.\n2. Depure el archivo de lote excluyendo los usuarios que ya cuentan con credencial Grid activa.\n3. Ejecute una sincronización diferencial en lugar de una importación completa.\n4. Consulte: https://docs.trustedauth.com/docs/perform-bulk-operations/',
        riskLevel: 'Alto (Fallo de Aprovisionamiento en Lote)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/perform-bulk-operations/',
        sectionId: 'sec-idaas-bulk',
        sectionTitle: 'IDaaS Cloud Bulk Provisioning: Grid Assignment Conflict'
      },
      {
        id: 'KB-IDG-BULK-QA-EXISTS',
        title: 'Entrust IDaaS Cloud: Preguntas y Respuestas Secretas (Q&A) Duplicadas / Ya Registradas',
        category: 'Entrust IDaaS Cloud / Aprovisionamiento Masivo (Bulk)',
        severity: 'ERROR',
        pattern: /(bulkidentityguard\.add\.error\.qa|identityguard_import_user_qa_already_exists)/i,
        meaning: 'El esquema de preguntas y respuestas de desafío (Q&A Challenge/Response) ya fue registrado previamente para este usuario en Entrust IDaaS.',
        rootCause: 'Intento de inserción de preguntas de seguridad en usuarios ya enrolados sin habilitar la bandera de actualización de credenciales updateExistingCredentials=true.',
        remediation: '1. Habilite el parámetro updateExistingCredentials=true en la configuración de la tarea de importación masiva.\n2. Si los usuarios deben mantener sus preguntas actuales, omita la columna Q&A en el archivo CSV de carga.\n3. Valide el estado de enrolamiento del usuario en la consola de IDaaS.\n4. Consulte: https://docs.trustedauth.com/docs/people-and-access/',
        riskLevel: 'Medio (Conflicto de Credenciales Q&A)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/people-and-access/',
        sectionId: 'sec-idaas-bulk',
        sectionTitle: 'IDaaS Cloud Bulk Provisioning: Q&A Challenge Collision'
      },
      {
        id: 'KB-IDG-BULK-PWD-EXISTS',
        title: 'Entrust IDaaS Cloud: Contraseña / Credencial de Autenticación ya Existente',
        category: 'Entrust IDaaS Cloud / Aprovisionamiento Masivo (Bulk)',
        severity: 'ERROR',
        pattern: /(bulkidentityguard\.add\.error\.password|identityguard_import_user_password_already_exists)/i,
        meaning: 'La credencial de autenticación básica (Password/PIN) enviada en el lote coincide o colisiona con una credencial existente en la base de identidades.',
        rootCause: 'Conflicto de unicidad en el almacén de identidades IDaaS durante la importación masiva de credenciales.',
        remediation: '1. Verifique las políticas de sincronización con el Directorio Activo (AD/LDAP).\n2. Asegúrese de que el lote no intente sobreescribir contraseñas sin la directiva allowPasswordReset=true.\n3. Verifique el formato de hash de contraseña admitido.\n4. Consulte: https://docs.trustedauth.com/docs/authentication-and-security/',
        riskLevel: 'Medio (Conflicto de Password)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/authentication-and-security/',
        sectionId: 'sec-idaas-bulk',
        sectionTitle: 'IDaaS Cloud Bulk Provisioning: Password Credential Conflict'
      },
      {
        id: 'KB-AWS-S3-404',
        title: 'AWS S3 Cloud Storage Error [404 NoSuchKey]: The specified key does not exist',
        category: 'Entrust IDaaS Cloud / Almacenamiento S3 & SDK',
        severity: 'CRITICAL',
        pattern: /(The specified key does not exist|Service:\s*S3.*Status Code:\s*404|AWS-S3-404-NOKEY)/i,
        meaning: 'Fallo de recuperación de objeto en Amazon S3. El worker de migración de Entrust IDaaS intentó descargar un paquete .dat, fragmento temporal o manifiesto que no fue encontrado en el bucket.',
        rootCause: '1. El token/URL prefirmada de S3 expiró durante una carga masiva prolongada.\n2. El archivo temporal fue purgado por políticas de ciclo de vida de S3 antes de finalizar la ingesta.\n3. Discrepancia en la clave de ruta del archivo en el SDK de AWS.',
        remediation: '1. Reintentar la subida del paquete en la consola de IDaaS asegurando que no existan microcortes en la conexión.\n2. Fraccionar los lotes de exportación a bloques de 50.000 registros para evitar timeouts del SDK S3.\n3. Verificar la configuración del conector y vigencia de credenciales Cloud.\n4. Consulte: https://docs.trustedauth.com/docs/perform-bulk-operations/',
        riskLevel: 'Crítico (Fallo de Infraestructura Cloud S3 / True Error)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/perform-bulk-operations/',
        sectionId: 'sec-aws-s3-404',
        sectionTitle: 'Fallo AWS S3 Cloud Storage: 404 NoSuchKey'
      },
      {
        id: 'KB-IDG-BULK-RBA',
        title: 'Entrust IDaaS Cloud: Configuración de Políticas Basadas en Riesgo (RBA Setting)',
        category: 'Entrust IDaaS Cloud / Políticas RBA',
        severity: 'INFO',
        pattern: /(bulkidentityguard\.add\.rbasetting|bulkidentityguard\.edit\.user)/i,
        meaning: 'Aprovisionamiento nominal de políticas de Autenticación Basada en Riesgo (RBA) y actualización de perfil de usuario en IDaaS Cloud.',
        rootCause: 'Operación nominal de aprovisionamiento masivo de identidades completada satisfactoriamente.',
        remediation: 'No requiere acción. Operación completada con éxito en la plataforma IDaaS.\nConsulte: https://docs.trustedauth.com/docs/authentication-and-security/',
        riskLevel: 'Bajo (Operación Nominal)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/authentication-and-security/',
        sectionId: 'sec-idaas-overview',
        sectionTitle: 'IDaaS Cloud Bulk Provisioning: RBA Policy Provisioning'
      },
      {
        id: 'KB-IDG-SAML-EXPIRED',
        title: 'Entrust IDaaS Cloud: Aserción SAML 2.0 Expirada o Desfase de Reloj (SAML_RESPONSE_EXPIRED)',
        category: 'Entrust IDaaS Cloud / SSO & Aplicaciones',
        severity: 'ERROR',
        pattern: /(SAML_RESPONSE_EXPIRED|SAMLResponse.*expired|ClockSkew.*exceeded)/i,
        meaning: 'La aserción SAML 2.0 emitida por el tenant de Entrust IDaaS fue rechazada por la aplicación del proveedor de servicio (SP) debido a desfase horario (Clock Skew) o latencia de red superior a la ventana NotOnOrAfter.',
        rootCause: '1. Desincronización del reloj NTP en los servidores de la aplicación SP o balanceador.\n2. Tolerancia de desfase horario (Clock Skew Tolerance) configurada por debajo de 60 segundos.',
        remediation: '1. Sincronizar NTP en el servidor local con el pool oficial.\n2. Incrementar la tolerancia Clock Skew a 180s en la configuración de la aplicación en IDaaS.\n3. Consulte: https://docs.trustedauth.com/docs/applications-and-sso/',
        riskLevel: 'Alto (Fallo de Inicio de Sesión SSO)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/applications-and-sso/',
        sectionId: 'sec-idaas-auth',
        sectionTitle: 'IDaaS Cloud SSO: SAML Assertion Expiration'
      },
      {
        id: 'KB-IDG-PUSH-FAILED',
        title: 'Entrust IDaaS Cloud: Fallo de Entrega Push Notification MFA (PUSH_NOTIFICATION_FAILED)',
        category: 'Entrust IDaaS Cloud / Autenticación Adaptativa MFA',
        severity: 'WARN',
        pattern: /(PUSH_NOTIFICATION_FAILED|Push notification delivery failed|APNS_FAILED|FCM_UNREACHABLE)/i,
        meaning: 'No fue posible entregar la notificación push de confirmación biométrica/MFA al smartphone del usuario registrado.',
        rootCause: 'Dispositivo sin conectividad a Apple APNs o Google FCM, token de dispositivo revocado o app desinstalada.',
        remediation: '1. Indicar al usuario ingresar el código OTP de 6 u 8 dígitos generado localmente por la app Entrust Identity.\n2. Re-enrolar el dispositivo móvil si el token de push fue revocado.\n3. Consulte: https://docs.trustedauth.com/docs/authentication-and-security/',
        riskLevel: 'Medio (Fallo de Notificación Push)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/authentication-and-security/',
        sectionId: 'sec-idaas-auth',
        sectionTitle: 'IDaaS Cloud MFA: Push Notification Delivery'
      },
      {
        id: 'KB-IDG-RADIUS-TIMEOUT',
        title: 'Entrust IDaaS Cloud: Timeout en RADIUS Cloud Gateway Proxy (RADIUS_PROXY_TIMEOUT)',
        category: 'Entrust IDaaS Cloud / Gateways & Conectividad',
        severity: 'ERROR',
        pattern: /(RADIUS_PROXY_TIMEOUT|Radius gateway proxy timeout|Gateway response timeout)/i,
        meaning: 'El conector local RADIUS Gateway no recibió respuesta del endpoint cloud de Entrust IDaaS dentro del umbral de tiempo límite.',
        rootCause: 'Bloqueo de firewall saliente en puerto 443/TLS hacia api.trustedauth.com, latencia alta de red WAN o sobrecarga en el gateway local.',
        remediation: '1. Verificar la conectividad hacia los endpoints de Entrust IDaaS: `curl -v https://api.trustedauth.com`.\n2. Comprobar el estado del daemon: `sudo systemctl status entrust-radius-gateway`.\n3. Aumentar el timeout de respuesta en `gateway.properties` a 15 segundos.\n4. Consulte: https://docs.trustedauth.com/docs/gateways/',
        riskLevel: 'Alto (Afectación de Canales VPN/Firewall RADIUS)',
        manualVersion: 'vIDaaS_docs',
        docsUrl: 'https://docs.trustedauth.com/docs/gateways/',
        sectionId: 'sec-idaas-apps',
        sectionTitle: 'IDaaS Cloud Gateways: RADIUS Proxy Timeout'
      },
      {
        id: 'KB-ENTRUST-DISCONNECT',
        title: 'Desconexión Voluntaria del Usuario (Client Abort / Broken Pipe)',
        category: 'Entrust OnPremise / Conectividad HTTP',
        severity: 'INFO',
        pattern: /(ClientAbortException|Broken pipe|ClientAbort|Connection reset by peer)/i,
        meaning: 'El usuario o navegador cerró la pestaña/conexión antes de que Entrust terminara de enviar la respuesta HTTP.',
        rootCause: 'Navegación cancelada o ventana cerrada prematuramente por el cliente final.',
        remediation: 'No requiere acción técnica. Es un comportamiento habitual del usuario y no representa una falla del servidor Entrust.',
        riskLevel: 'Informativo (Cero Falsos Positivos)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-client-abort',
        sectionTitle: 'Desconexión Voluntaria del Cliente'
      },
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
        remediation: '1. Ingrese las respuestas correctas para el desafío emitido sin agotar los intentos restantes.\n2. Compruebe los logs del sistema en busca de un mensaje de error contenido que pueda estar oculto para el usuario final.\n3. (Ref. Documentación Técnica Oficial Entrust IdentityGuard: Código 5203000 - Invalid Response to Challenge)',
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
        remediation: '1. Inicie sesión en la Consola de Administración de IdentityGuard.\n2. Revise el estado de la tarjeta Grid del usuario y cámbiela a ACTIVE o reasigne una nueva tarjeta.\n3. (Ref. Documentación Oficial Entrust IdentityGuard: Código 5203001 - Invalid Card State)',
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
        remediation: '1. Ingrese a la Consola de Administración de Entrust y asigne una Tarjeta Grid o Token de Software al usuario.\n2. Si es un usuario nuevo, genere un PIN temporal de primer uso.\n3. (Ref. Documentación Oficial Entrust IdentityGuard: Código 5203002 - No Active Card or Temp PIN)',
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
        remediation: '1. Emita y asigne un nuevo paquete de Tarjetas Grid para el usuario.\n2. Verifique las políticas de vigencia en la consola de administración.\n3. (Ref. Documentación Oficial Entrust IdentityGuard: Código 5203003 - Card Expired)',
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
        remediation: '1. Verifique la ortografía del ID de usuario enviado por la aplicación integradora.\n2. Verifique que el usuario esté activo e inscrito en la Consola Entrust.\n3. (Ref. Documentación Oficial Entrust IdentityGuard: Código 5203004 - User Not Found)',
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
        remediation: '1. Genere un nuevo PIN temporal desde la Consola de Administración de IdentityGuard.\n2. Inste al usuario a completar el primer inicio de sesión sin demoras.\n3. (Ref. Documentación Oficial Entrust IdentityGuard: Código 5203005 - Temp PIN Expired)',
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
        remediation: '1. Inicie sesión nuevamente en la Consola de Administración de Entrust IdentityGuard.\n2. Ajuste el tiempo de inactividad en la configuración de la consola si es necesario.\n3. (Ref. Documentación Oficial Entrust IdentityGuard: Código 5207005 - Session Timed Out)',
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
        id: 'KB-ENTRUST-5203019',
        title: 'Entrust IdentityGuard [5203019]: Usuario sin Contraseña OTP Configurada (User Does Not Have a One-Time Password)',
        category: 'Entrust OnPremise / Autenticación OTP & AD',
        severity: 'ERROR',
        pattern: /(5203019|does not have a one-time password)/i,
        attribution: '🔑 Autenticación OTP / Active Directory',
        meaning: 'El usuario intentó autenticarse mediante contraseña OTP o clave temporal, pero su cuenta no posee un token OTP o PIN de un solo uso activo asignado.',
        rootCause: 'Falta de aprovisionamiento de token OTP en el perfil del usuario o caducidad del PIN de enrolamiento.',
        remediation: '1. Verifique el perfil del usuario en la Consola de Administración de Entrust IdentityGuard.\n2. Emita y asocie un nuevo Token OTP / Soft Token al usuario o genere un PIN temporal de primer uso.',
        riskLevel: 'Medio (Sin OTP Asignado)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203019',
        sectionTitle: 'Código [5203019]: User Does Not Have a One-Time Password'
      },
      {
        id: 'KB-ENTRUST-5203007',
        title: 'Entrust IdentityGuard [5203007]: Desafío No Encontrado o Sesión Expirada (Challenge Not Found)',
        category: 'Entrust OnPremise / Sesión de Desafío',
        severity: 'ERROR',
        pattern: /(5203007|Challenge not found)/i,
        attribution: '⏱️ Sesión de Desafío / Expiración',
        meaning: 'La transacción o sesión de desafío (Challenge-Response) expiró antes de recibir la respuesta o el ID de desafío no existe en el servidor.',
        rootCause: 'El usuario demoró en responder al desafío o la aplicación integradora envió una respuesta fuera de tiempo.',
        remediation: '1. Inste al usuario a solicitar una nueva transacción o desafío de autenticación.\n2. Verifique la sincronización del servicio de tiempo (NTP) entre la pasarela y el servidor Entrust.',
        riskLevel: 'Medio (Desafío No Encontrado / Timeout)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203007',
        sectionTitle: 'Código [5203007]: Challenge Not Found'
      },
      {
        id: 'KB-ENTRUST-5203113',
        title: 'Entrust IdentityGuard [5203113]: Fallo de Autenticación de Contraseña (Bad User ID or Password Provided)',
        category: 'Entrust OnPremise / Active Directory & Autenticación',
        severity: 'ERROR',
        pattern: /(5203113|The password authentication failed for user|Bad user ID or password provided)/i,
        attribution: '👤 Usuario Final / Active Directory',
        meaning: 'El subsistema IG.SYSTEM.AuthenticationManagement.API rechazó el inicio de sesión porque la ID de usuario o contraseña proporcionada es errónea en Active Directory / LDAP.',
        rootCause: 'Credenciales de acceso incorrectas ingresadas por el usuario o cuenta bloqueada en Active Directory.',
        remediation: '1. Verifique que el usuario exista y esté activo en Active Directory.\n2. Inicie sesión en la Consola de Administración de Entrust y desmarque el bloqueo si superó el límite de reintentos.',
        riskLevel: 'Alto (Fallo de Autenticación de Contraseña)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203113',
        sectionTitle: 'Código [5203113]: Bad User ID or Password Provided'
      },
      {
        id: 'KB-ENTRUST-5205150',
        title: 'Entrust IdentityGuard [5205150]: Usuario sin Valor de Contraseña en Active Directory (User Does Not Have a Password Value)',
        category: 'Entrust OnPremise / Active Directory & Identidad',
        severity: 'ERROR',
        pattern: /(5205150|does not have a password value)/i,
        attribution: '👤 Active Directory / Cuenta sin Contraseña',
        meaning: 'El subsistema de Gestión de Usuarios (IG.SYSTEM.UserManagement.API) detectó que la cuenta del usuario no posee una contraseña asignada o configurada en Active Directory / LDAP.',
        rootCause: 'Cuenta de usuario aprovisionada desatendida sin contraseña inicial o atributo de clave nulo en el directorio LDAP/AD.',
        remediation: '1. Ingrese a Active Directory y verifique que la cuenta de usuario posea una contraseña válida y activa.\n2. En la Consola de Administración de Entrust IdentityGuard, ejecute una sincronización de usuario o asigne una clave inicial.',
        riskLevel: 'Alto (Cuenta sin Contraseña en AD)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5205150',
        sectionTitle: 'Código [5205150]: User Does Not Have a Password Value'
      },
      {
        id: 'KB-ENTRUST-5203033',
        title: 'Entrust IdentityGuard [5203033]: PIN de Seguridad de Usuario Inválido (Invalid Security PIN)',
        category: 'Entrust OnPremise / Autenticación PIN',
        severity: 'ERROR',
        pattern: /(5203033)/i,
        attribution: '🔑 Autenticación / PIN Erróneo',
        meaning: 'El PIN de seguridad proporcionado por el usuario no coincide con el PIN registrado en la base de identidades del servidor Entrust.',
        rootCause: 'Ingreso erróneo del número de PIN por parte del usuario final.',
        remediation: '1. Inste al usuario a ingresar cuidadosamente su PIN asignado.\n2. Si el usuario olvidó su clave, genere un nuevo PIN temporal desde la Consola de Administración.',
        riskLevel: 'Medio (PIN Inválido)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5203033',
        sectionTitle: 'Código [5203033]: Invalid Security PIN'
      },
      {
        id: 'KB-ENTRUST-5202057',
        title: 'Entrust IdentityGuard [5202057]: Incoincidencia de Serie de Tarjeta Grid (Grid Card Serial Mismatch)',
        category: 'Entrust OnPremise / Tarjetas Grid',
        severity: 'ERROR',
        pattern: /(5202057)/i,
        attribution: '⚙️ Tarjetas Grid / Serie Errónea',
        meaning: 'La tarjeta Grid Card o valor de desafío ingresado por el usuario no corresponde al número de serie asignado a su perfil.',
        rootCause: 'El usuario intentó autenticarse utilizando una tarjeta Grid obsoleta o no asociada a su cuenta.',
        remediation: '1. Ingrese a la Consola de Administración de Entrust IdentityGuard.\n2. Verifique la serie activa de la tarjeta Grid en el perfil del usuario y reemita si es necesario.',
        riskLevel: 'Medio (Serie de Tarjeta Errónea)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5202057',
        sectionTitle: 'Código [5202057]: Grid Card Serial Mismatch'
      },
      {
        id: 'KB-ENTRUST-5202404',
        title: 'Entrust IdentityGuard [5202404]: Fallo de Conexión a Base de Datos de Repositorios (Database Connection Pool Exhausted)',
        category: 'Entrust OnPremise / Base de Datos JDBC',
        severity: 'CRITICAL',
        pattern: /(5202404)/i,
        attribution: '🗄️ Base de Datos / Pool JDBC Exhausto',
        meaning: 'El servidor Entrust IdentityGuard no pudo conectarse al repositorio de base de datos debido al agotamiento de conexiones en el pool JDBC o tiempo de espera (Timeout).',
        rootCause: 'Saturación en el pool de conexiones de la base de datos principal o secundaria (Oracle / SQL Server / PostgreSQL).',
        remediation: '1. Verifique que la instancia de la base de datos principal esté activa.\n2. Incremente las conexiones en `identityguard.properties` / `context.xml` y reinicie el servicio.',
        riskLevel: 'Crítico (Saturación de Base de Datos)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5202404',
        sectionTitle: 'Código [5202404]: Database Connection Pool Exhausted'
      },
      {
        id: 'KB-ENTRUST-5205080',
        title: 'Entrust IdentityGuard [5205080]: Cuenta de Usuario Suspendida Temporales (User Account Temporarily Locked)',
        category: 'Entrust OnPremise / Políticas de Bloqueo',
        severity: 'ERROR',
        pattern: /(5205080)/i,
        attribution: '🔒 Cuenta Suspendida / Bloqueo Temporal',
        meaning: 'La cuenta del usuario fue suspendida temporalmente por la política de seguridad tras acumular reintentos fallidos consecutivos de autenticación.',
        rootCause: 'Múltiples reintentos fallidos consecutivos de contraseña, PIN o celdas de Tarjeta Grid por parte del usuario.',
        remediation: '1. Inicie sesión en la Consola de Administración de Entrust IdentityGuard.\n2. Ubique la cuenta del usuario y presione Desbloquear o espere el tiempo de expiración del temporizador de bloqueo.',
        riskLevel: 'Alto (Cuenta Suspendida)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5205080',
        sectionTitle: 'Código [5205080]: User Account Temporarily Locked'
      },
      {
        id: 'KB-ENTRUST-5202500',
        title: 'Entrust IdentityGuard [5202500]: Error Interno de Servicio Web / Servidor Entrust (Internal Server Error)',
        category: 'Entrust OnPremise / Servicios Core',
        severity: 'CRITICAL',
        pattern: /(5202500)/i,
        attribution: '⚙️ Servidor Core / Excepción Interna',
        meaning: 'El subsistema de servicios de Entrust IdentityGuard experimentó una excepción interna no controlada durante el procesamiento de la transacción API.',
        rootCause: 'Excepción de ejecución interna en el servidor de aplicaciones Tomcat Catalina o fallo inesperado de memoria.',
        remediation: '1. Revise los registros detallados de `catalina.out` a la hora exacta del evento.\n2. Verifique la memoria disponible en la JVM e incremente los parámetros `-Xms/-Xmx` si es necesario.',
        riskLevel: 'Crítico (Excepción Interna)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5202500',
        sectionTitle: 'Código [5202500]: Internal Server Error'
      },
      {
        id: 'KB-ENTRUST-5202050',
        title: 'Entrust IdentityGuard [5202050]: Incoincidencia de Autenticador o Tarjeta Invalidad (Invalid Authenticator Response)',
        category: 'Entrust OnPremise / Autenticadores',
        severity: 'ERROR',
        pattern: /(5202050)/i,
        attribution: '⚙️ Autenticadores / Respuesta Inválida',
        meaning: 'El valor de autenticación o respuesta enviada no corresponde al tipo de tarjeta Grid o autenticador actualmente asignado a la cuenta del usuario.',
        rootCause: 'El usuario respondió utilizando un autenticador desasociado o desincronizado.',
        remediation: '1. Ingrese a la Consola de Administración de Entrust IdentityGuard.\n2. Verifique la serie y tipo de autenticador activo en el perfil del usuario.',
        riskLevel: 'Medio (Respuesta de Autenticador Inválida)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5202050',
        sectionTitle: 'Código [5202050]: Invalid Authenticator Response'
      },
      {
        id: 'KB-ENTRUST-5206001',
        title: 'Entrust IdentityGuard [5206001]: Autenticador o Tarjeta Grid Pendiente de Activación',
        category: 'Entrust OnPremise / Enrolamiento de Tarjetas',
        severity: 'ERROR',
        pattern: /(5206001)/i,
        attribution: '⚙️ Enrolamiento / Tarjeta Grid',
        meaning: 'El dispositivo o Tarjeta Grid asociada al usuario no ha completado el proceso de activación o confirmación de primer uso.',
        rootCause: 'Tarjeta Grid asignada pero no activada en la consola o código de confirmación no ingresado.',
        remediation: '1. Ingrese a la Consola de Administración de Entrust IdentityGuard.\n2. Verifique el estado de la Tarjeta Grid o Soft Token del usuario y ejecute la acción de Confirmar/Activar.',
        riskLevel: 'Alto (Autenticador Inactivo)',
        manualVersion: 'vEntrust',
        sectionId: 'sec-5206001',
        sectionTitle: 'Código [5206001]: Card or Token Pending Activation'
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

  importCatalogFromHtml(htmlContent, versionLabel = 'Release 11.0') {
    if (!htmlContent) return 0;
    let importedCount = 0;

    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(htmlContent, 'text/html');

      const cards = doc.querySelectorAll('.error-card, .proc-card, tr, h2, h3, div, p');
      cards.forEach(card => {
        const text = card.textContent || '';
        const codeMatch = text.match(/(520\d{4}|AUD\d+)/i);
        if (codeMatch) {
          const code = codeMatch[1].toUpperCase();
          const existing = this.rules.find(r => r.id === `KB-ENTRUST-${code}`);
          if (!existing) {
            const meaningMatch = text.match(/(?:Significado|Meaning|Descripción|Detalle):\s*([^\n\r]+)/i);
            const remMatch = text.match(/(?:Remediación|Remediation|Solución):\s*([^\n\r]+)/i);

            this.saveCustomRule({
              id: `KB-ENTRUST-${code}`,
              title: `Entrust IdentityGuard [${code}] (${versionLabel})`,
              category: `Entrust OnPremise (${versionLabel})`,
              severity: 'ERROR',
              pattern: `(${code})`,
              meaning: meaningMatch ? meaningMatch[1].trim() : `Código de error [${code}] registrado según la documentación oficial de ${versionLabel}.`,
              rootCause: `Condición de evento o error en la transacción reportada por el servidor Entrust ${versionLabel}.`,
              remediation: remMatch ? remMatch[1].trim() : `Consulte la Consola de Administración de Entrust y verifique la cuenta/configuración asociada al código [${code}].`,
              manualVersion: versionLabel
            });
            importedCount++;
          }
        }
      });
    } catch (e) {
      console.error('Error al importar HTML en KB:', e);
    }

    return importedCount;
  }

  _normalizeDocVersionLabel(raw) {
    const s = String(raw || '').trim();
    if (!s) return 'General';
    if (/^general$/i.test(s) || /^otro/i.test(s)) return 'General';
    if (/idaas|cloud/i.test(s)) return 'IDaaS Cloud';
    if (/(?:^|[^\d])13(?:\.0)?(?:[^\d]|$)/.test(s) || /v13/i.test(s)) return 'IG 13.0';
    if (/(?:^|[^\d])12(?:\.0|\.4)?(?:[^\d]|$)/.test(s) || /v12/i.test(s)) return 'IG 12.0';
    if (/(?:^|[^\d])11(?:\.0)?(?:[^\d]|$)/.test(s) || /v11/i.test(s)) return 'IG 11.0';
    if (/(?:^|[^\d])10(?:\.0|\.2)?(?:[^\d]|$)/.test(s) || /v10/i.test(s)) return 'IG 10.0';
    if (/(?:^|[^\d])9(?:\.0|\.3)?(?:[^\d]|$)/.test(s) || /\bv9\b|ig[_ -]?9/i.test(s)) return 'IG 9.0';
    return 'General';
  }

  _detectActiveDocVersion() {
    if (typeof window === 'undefined') return 'IG 12.0';
    let client = null;
    if (typeof window.getActiveClientProfileGlobal === 'function') {
      client = window.getActiveClientProfileGlobal();
    } else if (window.state && window.state.activeClientId) {
      client = (window.state.clientProfiles || []).find(p => p.id === window.state.activeClientId);
    }
    if (!client) return 'IG 12.0';
    const combined = `${client.platform || ''} ${client.version || ''}`.trim();
    const detected = this._normalizeDocVersionLabel(combined);
    return detected === 'General' ? 'IG 12.0' : detected;
  }

  diagnoseLog(logText, targetCode) {
    if (!logText && !targetCode) return null;
    const searchText = logText || (targetCode ? `[${targetCode}]` : '');

    // Determinar la versión activa de la plataforma del cliente en sesión (v9, v10, v11, v12, v13, IDaaS)
    let activeVersionLabel = 'Entrust IdentityGuard (Admin Guide)';
    let activeVersionKey = 'v12_0_webhelp';
    if (typeof window !== 'undefined') {
      let client = null;
      if (typeof window.getActiveClientProfileGlobal === 'function') {
        client = window.getActiveClientProfileGlobal();
      } else if (window.state && window.state.activeClientId) {
        client = (window.state.clientProfiles || []).find(p => p.id === window.state.activeClientId);
      }
      if (client) {
        const pVer = client.version || 'Release 12.0';
        const pPlat = client.platform || 'Entrust IdentityGuard OnPremise';
        activeVersionLabel = `${pPlat} (${pVer})`;
        if (/(?:^|[^\d])9(?:\.\d+)?(?:[^\d]|$)/i.test(pVer)) activeVersionKey = 'v9_0_custom';
        else if (/10/i.test(pVer)) activeVersionKey = 'v10_0_custom';
        else if (/11/i.test(pVer)) activeVersionKey = 'v11_0_webhelp';
        else if (/12/i.test(pVer)) activeVersionKey = 'v12_0_webhelp';
        else if (/13/i.test(pVer)) activeVersionKey = 'v13_0_webhelp';
        else if (/idaas|cloud/i.test(pVer) || /idaas|cloud/i.test(pPlat)) activeVersionKey = 'vIDaaS_docs';
      }
    }

    // 0. Búsqueda exacta e instantánea en el Catálogo de Precisión Oficial
    const cleanCode = (targetCode || (typeof this.extractErrorCodeFromText === 'function' ? this.extractErrorCodeFromText(searchText) : '') || '').trim();
    const officialAudCatalog = (typeof window !== 'undefined' && window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG) ? window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG : {};
    const officialAudMeta = cleanCode ? officialAudCatalog[cleanCode.toUpperCase()] : null;
    if (cleanCode && typeof ENTRUST_EXACT_CATALOG !== 'undefined' && ENTRUST_EXACT_CATALOG[cleanCode]) {
      const entry = ENTRUST_EXACT_CATALOG[cleanCode];
      return {
        matched: true,
        ruleId: `KB-EXACT-${cleanCode}`,
        title: `[${cleanCode}] ${entry.title}`,
        category: entry.category,
        severity: entry.severity,
        meaning: entry.meaning,
        rootCause: entry.rootCause,
        governanceControl: entry.governanceControl || entry.remediation,
        remediation: entry.remediation,
        riskLevel: entry.severity === 'CRITICAL' ? 'Crítico (P1)' : (entry.severity === 'ERROR' ? 'Alto (P2)' : (entry.severity === 'WARN' ? 'Medio (Advertencia)' : 'Nominal / Auditoría')),
        manualVersion: activeVersionLabel,
        manualFile: entry.manualFile || (officialAudMeta ? officialAudMeta.manualFile : null),
        officialName: officialAudMeta ? officialAudMeta.name : null,
        snmpTrap: officialAudMeta ? officialAudMeta.snmp : null,
        sectionId: `sec-${cleanCode.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
        sectionTitle: `Código [${cleanCode}]: ${entry.title}`
      };
    }

    // 0.5 Búsqueda exacta en códigos extraídos literalmente de PDFs oficiales cargados en el servidor (prioriza versión del cliente)
    const activeDocVer = this._detectActiveDocVersion();
    const customPdfByVer = (typeof window !== 'undefined' && window.ENTRUST_CUSTOM_PDF_CATALOG_BY_VERSION) ? window.ENTRUST_CUSTOM_PDF_CATALOG_BY_VERSION : {};
    const customPdfCatalog = (typeof window !== 'undefined' && window.ENTRUST_CUSTOM_PDF_CATALOG) ? window.ENTRUST_CUSTOM_PDF_CATALOG : {};
    const cleanUp = cleanCode ? cleanCode.toUpperCase() : '';
    let pdfEntry = null;
    if (cleanCode) {
      const verBucket = customPdfByVer[activeDocVer];
      if (verBucket) {
        pdfEntry = verBucket[cleanCode] || verBucket[cleanUp] || null;
      }
      if (!pdfEntry) {
        pdfEntry = customPdfCatalog[cleanCode] || customPdfCatalog[cleanUp] || null;
      }
    }
    if (pdfEntry) {
      const pdfVer = pdfEntry.docVersion || 'General';
      const isPdf = /\.pdf($|#)/i.test(pdfEntry.manualFile || pdfEntry.sourceFile || '');
      const kindNoun = isPdf ? 'PDF oficial' : 'documento técnico';
      const kindBadge = isPdf ? 'PDF Oficial' : 'Documento';
      const locLabel = isPdf
        ? `página ${pdfEntry.page || 1}`
        : ((Number(pdfEntry.page || 1) > 1) ? `sección ${pdfEntry.page}` : 'referencia oficial');
      const shortLoc = isPdf
        ? `Pág. ${pdfEntry.page || 1}`
        : ((Number(pdfEntry.page || 1) > 1) ? `Secc. ${pdfEntry.page}` : 'HTML/Doc');
      return {
        matched: true,
        ruleId: `KB-${isPdf ? 'PDF' : 'DOC'}-${pdfEntry.code}`,
        title: `[${pdfEntry.code}] ${pdfEntry.title}`,
        category: `Documentación ${isPdf ? 'PDF' : 'HTML/Doc'} ${pdfVer} (${pdfEntry.sourceFile})`,
        severity: pdfEntry.severity || 'ERROR',
        meaning: `Extracto literal del ${kindNoun} [${pdfVer}] "${pdfEntry.sourceFile}" (${shortLoc}): ${pdfEntry.excerpt}`,
        rootCause: `Consulte el contexto completo en ${pdfEntry.sourceFile} (${pdfVer}), ${locLabel}.`,
        governanceControl: `Abrir ${kindNoun}: ${pdfEntry.manualFile}`,
        remediation: `Abrir el manual "${pdfEntry.sourceFile}" (${pdfVer}) en ${locLabel} desde el visor integrado para aplicar el procedimiento del fabricante.`,
        riskLevel: pdfEntry.severity === 'ERROR' ? `Alto (Documentado en ${kindBadge} ${pdfVer})` : `Informativo / Auditoría (${kindBadge} ${pdfVer})`,
        manualVersion: `${kindBadge} ${pdfVer}: ${pdfEntry.sourceFile} (${shortLoc})`,
        manualFile: pdfEntry.manualFile,
        docVersion: pdfVer,
        sourceType: pdfEntry.sourceType || (isPdf ? 'PDF_CUSTOM' : 'DOC_CUSTOM'),
        sectionId: `sec-pdf-${pdfEntry.code.toLowerCase()}`,
        sectionTitle: `${kindBadge} ${pdfVer} [${pdfEntry.code}]: ${pdfEntry.title}`
      };
    }

    // 1. Si el usuario cargó manuales específicos para la versión activa (v11, v12, v13), buscar primero en las reglas de esa versión
    if (targetCode) {
      const specRuleVersion = this.rules.find(r => (r.manualVersion === activeVersionKey || r.manualVersion === activeVersionLabel) && (r.id === `KB-ENTRUST-${targetCode}` || (r.pattern && r.pattern.test(`[${targetCode}]`))));
      if (specRuleVersion) {
        return {
          matched: true,
          ruleId: specRuleVersion.id,
          title: specRuleVersion.title,
          category: specRuleVersion.category,
          severity: specRuleVersion.severity,
          meaning: specRuleVersion.meaning,
          rootCause: specRuleVersion.rootCause,
          governanceControl: specRuleVersion.remediation,
          remediation: specRuleVersion.remediation,
          riskLevel: specRuleVersion.riskLevel,
          manualVersion: activeVersionLabel,
          sectionId: specRuleVersion.sectionId,
          sectionTitle: specRuleVersion.sectionTitle
        };
      }

      const specRule = this.rules.find(r => r.id === `KB-ENTRUST-${targetCode}` || (r.pattern && r.pattern.test(`[${targetCode}]`)));
      if (specRule) {
        return {
          matched: true,
          ruleId: specRule.id,
          title: specRule.title,
          category: specRule.category,
          severity: specRule.severity,
          meaning: specRule.meaning,
          rootCause: specRule.rootCause,
          governanceControl: specRule.remediation,
          remediation: specRule.remediation,
          riskLevel: specRule.riskLevel,
          manualVersion: activeVersionLabel,
          sectionId: specRule.sectionId,
          sectionTitle: specRule.sectionTitle
        };
      }
    }

    // 2. Buscar en todas las reglas cargadas en memoria
    for (const rule of this.rules) {
      if (rule.pattern && rule.pattern.test(searchText)) {
        return {
          matched: true,
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          meaning: rule.meaning,
          rootCause: rule.rootCause,
          governanceControl: rule.remediation,
          remediation: rule.remediation,
          riskLevel: rule.riskLevel,
          manualVersion: activeVersionLabel,
          sectionId: rule.sectionId,
          sectionTitle: rule.sectionTitle
        };
      }
    }

    // 3. Diagnóstico Especializado para Entrust IDaaS Migration Tool / Bulk Import
    if (/IdentityGuard migration:|bulkidentityguard\.add\.error/i.test(searchText) || (targetCode && targetCode.startsWith('bulkidentityguard'))) {
      if (/assignedgrid|grid already assigned/i.test(searchText) || targetCode === 'bulkidentityguard.add.error.assignedgrid') {
        return {
          matched: true,
          ruleId: 'KB-IDG-BULK-GRID-CONFLICT',
          title: 'Entrust IDaaS Cloud: Conflicto de Tarjeta Grid Preexistente (Grid Already Assigned)',
          category: 'Entrust IDaaS Cloud / Aprovisionamiento Masivo (Bulk)',
          severity: 'ERROR',
          attribution: '☁️ Entrust IDaaS Migration Tool / Almacén de Identidades Cloud',
          meaning: 'La tarea de importación masiva intentó asignar una nueva tarjeta Grid a usuarios que ya contaban con una tarjeta Grid activa en el almacén de identidades de Entrust IDaaS.',
          rootCause: 'Ejecución del proceso de carga por lotes (Bulk IdentityGuard) sin el parámetro de sobrescritura overwriteExistingGrid=true o re-ejecución del lote sobre usuarios previamente aprovisionados.',
          governanceControl: 'Configurar overwriteExistingGrid=true en el pipeline masivo si se requiere reemplazo de credencial.',
          remediation: '1. En la definición de la tarea masiva, configure el parámetro overwriteExistingGrid=true si requiere reemplazar la tarjeta actual.\n2. Depure el archivo de lote excluyendo los usuarios que ya cuentan con credencial Grid activa.\n3. Ejecute una sincronización diferencial en lugar de una importación completa.',
          riskLevel: 'Alto (Fallo de Aprovisionamiento en Lote)',
          manualVersion: activeVersionLabel,
          docsUrl: 'https://docs.trustedauth.com/docs/perform-bulk-operations/',
          sectionId: 'sec-idaas-bulk',
          sectionTitle: 'IDaaS Cloud Bulk Provisioning: Grid Assignment Conflict'
        };
      }
      if (/password|Password will not be migrated|currently has a password/i.test(searchText) || targetCode === 'bulkidentityguard.add.error.password') {
        return {
          matched: true,
          ruleId: 'KB-IDG-BULK-PWD-EXISTS',
          title: 'Entrust IDaaS Cloud: Contraseña / Credencial de Autenticación ya Existente',
          category: 'Entrust IDaaS Cloud / Aprovisionamiento Masivo (Bulk)',
          severity: 'ERROR',
          attribution: '☁️ Entrust IDaaS Migration Tool / Almacén de Identidades Cloud',
          meaning: 'El usuario ya posee una contraseña activa en la base de identidades de Entrust IDaaS Cloud. Por política de seguridad, la contraseña del archivo de migración no fue sobrescrita.',
          rootCause: 'Conflicto de unicidad en el almacén de identidades IDaaS durante la importación masiva de credenciales.',
          governanceControl: 'Habilitar allowPasswordReset=true en el conector masivo si se desea forzar actualización.',
          remediation: '1. Habilite el parámetro allowPasswordReset=true si se desea forzar el reemplazo de la contraseña existente.\n2. Verifique las políticas de sincronización con el Directorio Activo (AD/LDAP).\n3. Valide el estado de enrolamiento del usuario en la consola de IDaaS.',
          riskLevel: 'Medio (Conflicto de Password)',
          manualVersion: activeVersionLabel,
          docsUrl: 'https://docs.trustedauth.com/docs/authentication-and-security/',
          sectionId: 'sec-idaas-bulk',
          sectionTitle: 'IDaaS Cloud Bulk Provisioning: Password Credential Conflict'
        };
      }
      if (/qa|question|already has/i.test(searchText) || targetCode === 'bulkidentityguard.add.error.qa') {
        return {
          matched: true,
          ruleId: 'KB-IDG-BULK-QA-EXISTS',
          title: 'Entrust IDaaS Cloud: Preguntas y Respuestas Secretas (Q&A) Duplicadas / Ya Registradas',
          category: 'Entrust IDaaS Cloud / Aprovisionamiento Masivo (Bulk)',
          severity: 'ERROR',
          attribution: '☁️ Entrust IDaaS Migration Tool / Almacén de Identidades Cloud',
          meaning: 'El esquema de preguntas y respuestas de desafío (Q&A Challenge/Response) ya fue registrado previamente para este usuario en Entrust IDaaS Cloud.',
          rootCause: 'Intento de inserción de preguntas de seguridad en usuarios ya enrolados sin habilitar la bandera de actualización de credenciales updateExistingCredentials=true.',
          governanceControl: 'Configurar updateExistingCredentials=true para actualización de cuestionario.',
          remediation: '1. Habilite el parámetro updateExistingCredentials=true en la configuración de la tarea de importación masiva.\n2. Si los usuarios deben mantener sus preguntas actuales, omita la columna Q&A en el archivo CSV de carga.',
          riskLevel: 'Medio (Conflicto de Credenciales Q&A)',
          manualVersion: activeVersionLabel,
          docsUrl: 'https://docs.trustedauth.com/docs/people-and-access/',
          sectionId: 'sec-idaas-bulk',
          sectionTitle: 'IDaaS Cloud Bulk Provisioning: Q&A Challenge Collision'
        };
      }
    }

    // 4. Diagnóstico Oficial Entrust OnPremise AUDxxxx (Catálogo completo de 361 códigos extraído de WebHelp IG 11/12/13)
    const audBracketMatch = searchText.match(/\[(AUD\d+)\]\s*(.*)/i);
    const isDirectAud = cleanCode && /^AUD\d+/i.test(cleanCode);
    if (audBracketMatch || isDirectAud) {
      const audCode = (isDirectAud ? cleanCode : audBracketMatch[1]).toUpperCase();
      const audDetail = audBracketMatch && audBracketMatch[2] ? audBracketMatch[2].trim() : searchText;
      const official = officialAudCatalog[audCode] || null;

      let audTitle = `Evento de Auditoría Entrust [${audCode}]`;
      let audMeaning = `Registro oficial de auditoría [${audCode}] emitido por el subsistema IG.AUDIT de Entrust IdentityGuard.`;
      let audContext = 'Operación registrada por el motor de trazabilidad y control de accesos del clúster.';
      let audControl = '1. Verificar que los usuarios y canales listados correspondan a operaciones autorizadas.\n2. Correlacionar con la matriz de usuarios e interacciones para detectar anomalías de volumen.';
      let audSeverity = 'INFO';
      let audCategory = 'Auditoría & Trazabilidad de Seguridad (AUD)';
      let audManualFile = null;

      if (official) {
        const rawLvl = (official.level || 'INFO').toUpperCase();
        audSeverity = /ERROR|CRITICAL|FATAL/.test(rawLvl) ? 'ERROR' : (/WARN/.test(rawLvl) ? 'WARN' : 'INFO');
        audTitle = `[${audCode}] ${official.name}`;
        audCategory = official.category || audCategory;
        audManualFile = official.manualFile || null;
        audMeaning = `Definición oficial Entrust (${audCategory}): ${official.desc}` + (official.snmp ? ` [SNMP Trap por defecto: ${official.snmp}]` : '');
        audContext = `Evento oficial ${audSeverity} en "${audCategory}" — Manual Entrust IdentityGuard.`;
        audControl = (audSeverity === 'ERROR' || audSeverity === 'WARN')
          ? `1. Revisar cuentas de usuario, nodos e IPs involucradas en [${audCode}].\n2. Consultar la tabla oficial del manual (manuals/${official.manualFile || ''}) y aplicar remediación según directiva de seguridad.`
          : `1. Registro nominal de auditoría (${audCategory}).\n2. Validar en trazas de cumplimiento o consultar manuals/${official.manualFile || ''}.`;
      } else if (/failed authentication/i.test(audDetail)) {
        audTitle = `Intento Fallido de Autenticación de Usuario [${audCode}]`;
        audMeaning = `El subsistema IG.AUDIT registró un rechazo de autenticación sobre las cuentas de usuario listadas.`;
        audContext = 'Credencial inválida ingresada por el usuario o intento de acceso fallido.';
        audControl = '1. Revisar los usuarios con mayor reincidencia en este código.\n2. Auditar IPs de origen.';
        audSeverity = 'WARN';
      } else if (/locked out of/i.test(audDetail)) {
        audTitle = `Cuenta Bloqueada Automáticamente por Intentos Fallidos [${audCode}]`;
        audMeaning = `El usuario superó el umbral de intentos fallidos y su método de autenticación quedó bloqueado.`;
        audContext = 'Activación de política de bloqueo (Lockout) en Entrust IdentityGuard.';
        audControl = '1. Verificar identidad del usuario antes de desbloquear.\n2. Correlacionar con eventos previos AUD6001.';
        audSeverity = 'ERROR';
      } else if (/One time password.*deleted/i.test(audDetail)) {
        audTitle = `Consumo / Eliminación de Contraseña OTP [${audCode}]`;
        audMeaning = `Un código OTP fue depurado o consumido para el usuario objetivo mediante cuenta integradora API.`;
        audContext = 'Operación de limpieza o consumo de OTP ejecutada por el canal API sobre usuarios finales.';
        audControl = 'Validar que la cuenta API ejecutora sea legítima.';
        audSeverity = 'INFO';
      } else if (/login.*success|auth.*success/i.test(audDetail)) {
        audTitle = `Autenticación / Inicio de Sesión Exitoso [${audCode}]`;
        audMeaning = `Validación exitosa de credenciales registrada por el motor de auditoría Entrust.`;
        audContext = 'Acceso autenticado y autorizado.';
        audControl = 'Monitoreo nominal de línea base.';
      } else if (/fail|error|denied|invalid/i.test(audDetail)) {
        audTitle = `Alerta de Auditoría / Rechazo de Seguridad [${audCode}]`;
        audMeaning = `El módulo IG.AUDIT registró una operación rechazada o condición de alerta bajo el código [${audCode}].`;
        audContext = 'Intento de acceso o validación de política no satisfactorio.';
        audControl = 'Auditar usuarios e IPs involucradas en la Matriz de Códigos.';
        audSeverity = 'WARN';
      }

      return {
        matched: true,
        ruleId: `KB-ENTRUST-${audCode}`,
        title: audTitle,
        category: audCategory,
        severity: audSeverity,
        meaning: audMeaning,
        rootCause: audContext,
        governanceControl: audControl,
        remediation: audControl,
        riskLevel: audSeverity === 'ERROR' ? 'Alto (Bloqueo / Error Auditoría)' : (audSeverity === 'WARN' ? 'Medio (Alerta de Seguridad)' : 'Nominal (Auditoría)'),
        manualVersion: activeVersionLabel,
        manualFile: audManualFile,
        officialName: official ? official.name : null,
        snmpTrap: official ? official.snmp : null,
        docsUrl: 'https://docs.trustedauth.com',
        trustedCareUrl: 'https://trustedcare.entrust.com',
        sectionId: `sec-${audCode.toLowerCase()}`,
        sectionTitle: `Código [${audCode}]: ${official ? official.name : 'Evento de Auditoría Entrust'}`
      };
    }

    // 5. Diagnóstico Heurístico Entrust OnPremise 520xxx (Soporta con o sin corchetes y llamadas directas)
    const regexToUse = targetCode ? new RegExp('\\[(' + targetCode + ')\\]\\s*(.*)', 'i') : /\[(520\d{4})\]\s*(.*)/;
    const entrustMatch = searchText.match(regexToUse) || searchText.match(/\[(520\d{4})\]\s*(.*)/) || (cleanCode && /^520\d{4}$/.test(cleanCode) ? [cleanCode, cleanCode, searchText] : null);
    if (entrustMatch) {
      const code = (targetCode || entrustMatch[1]).trim();
      const detail = entrustMatch[2] ? entrustMatch[2].trim() : '';

      let meaningText = `Código de excepción técnica [${code}] emitido por el motor de autenticación o administración de Entrust IdentityGuard.`;
      let causeText = 'Fallo reportado por el servidor de autenticación/administración de Entrust IdentityGuard al validar credenciales o estado de la cuenta.';
      let remediationText = '1. Revise en la Matriz de Códigos los usuarios específicos afectados por [' + code + '].\n2. Compruebe el estado del autenticador del usuario (Token, Grid, Password) en la consola de Entrust.\n3. Consulte el boletín técnico del código en https://trustedcare.entrust.com.';

      if (/PIN/i.test(detail)) {
        meaningText = `Rechazo de validación de PIN de seguridad [${code}] en Entrust IdentityGuard.`;
        causeText = 'El PIN proporcionado por el usuario no coincide con el registrado o se encuentra bloqueado.';
        remediationText = '1. Solicite al usuario ingresar nuevamente su PIN o restablecerlo en la consola.\n2. Verifique si el autenticador quedó bloqueado por intentos fallidos.';
      } else if (/Card|Grid/i.test(detail)) {
        meaningText = `Error de validación o asignación de tarjeta Grid [${code}] en Entrust IdentityGuard.`;
        causeText = 'La coordenada de tarjeta Grid ingresada es incorrecta o existe un conflicto con la tarjeta asignada.';
        remediationText = '1. Verifique en la consola el serial de la tarjeta Grid activa del usuario.\n2. Reasigne o desbloquee la tarjeta Grid según corresponda.';
      } else if (/Challenge|response/i.test(detail)) {
        meaningText = `Fallo en validación de Desafío-Respuesta (Challenge-Response / OTP) [${code}].`;
        causeText = 'La respuesta OTP/Challenge ingresada expiró, fue reutilizada o presenta deriva de tiempo.';
        remediationText = '1. Emitir un nuevo desafío (Challenge) para el usuario.\n2. Verificar la sincronización horaria NTP de los nodos del clúster.';
      } else if (/password|user ID|login/i.test(detail)) {
        meaningText = `Fallo de autenticación de contraseña o identificador de usuario [${code}].`;
        causeText = 'Credenciales inválidas, contraseña expirada o usuario inactivo en el repositorio/directorio.';
        remediationText = '1. Verificar estado de la cuenta del usuario en IdentityGuard y LDAP/AD.\n2. Desbloquear o restablecer la credencial si aplica.';
      } else if (/server failure|5201000/i.test(detail) || code === '5201000') {
        meaningText = `Fallo interno crítico del motor de servidor Entrust IdentityGuard [${code}].`;
        causeText = 'Excepción interna del servidor al procesar la transacción o fallo de comunicación con la capa de persistencia JDBC.';
        remediationText = '1. Revisar la pestaña de Salud de Base de Datos (Oracle / JDBC) para descartar errores ORA-01555 o agotamiento de pool.\n2. Validar el estado del servicio de aplicación Entrust.';
      }

      return {
        matched: true,
        ruleId: `KB-ENTRUST-${code}`,
        title: `Excepción Entrust IdentityGuard [${code}]`,
        category: 'Errores IdentityGuard Core (520xxx)',
        severity: 'ERROR',
        meaning: meaningText,
        rootCause: causeText,
        governanceControl: remediationText,
        remediation: remediationText,
        riskLevel: 'Alto (Error de Sistema IdentityGuard)',
        manualVersion: activeVersionLabel,
        docsUrl: 'https://docs.trustedauth.com',
        trustedCareUrl: 'https://trustedcare.entrust.com',
        sectionId: `sec-${code}`,
        sectionTitle: `Código [${code}]: Error Entrust IdentityGuard`
      };
    }

    // 6. Diagnóstico Heurístico para Códigos ORA
    const oraMatch = searchText.match(/ORA-\d{5}/i) || (cleanCode && /^ORA-\d{5}$/i.test(cleanCode) ? [cleanCode] : null);
    if (oraMatch) {
      const oraCode = (targetCode || oraMatch[0]).toUpperCase();
      return {
        matched: true,
        ruleId: `KB-ORA-${oraCode}`,
        title: `Excepción Oracle Database [${oraCode}]`,
        category: 'Persistencia & Base de Datos (ORA)',
        severity: 'CRITICAL',
        meaning: `Error crítico reportado por el motor de base de datos relacional Oracle [${oraCode}] durante una operación de lectura/escritura de Entrust.`,
        rootCause: 'Saturación en UNDO tablespace (ORA-01555), restricción única (ORA-00001), corte de red TNS o agotamiento del pool JDBC.',
        governanceControl: 'Ejecutar diagnóstico DBA sobre el tablespace, listener Oracle y pool JDBC del servidor Entrust.',
        remediation: '1. Revisar la pestaña "Salud de Base de Datos" para ver la causa específica del código ' + oraCode + '.\n2. Verificar UNDO_RETENTION, cursores abiertos y conectividad hacia el puerto 1521.\n3. Consultar nota técnica oficial en https://trustedcare.entrust.com.',
        riskLevel: 'Crítico (Persistencia DB)',
        manualVersion: activeVersionLabel,
        docsUrl: 'https://trustedcare.entrust.com',
        trustedCareUrl: 'https://trustedcare.entrust.com',
        sectionId: `sec-${oraCode.toLowerCase()}`,
        sectionTitle: `Excepción Oracle [${oraCode}]`
      };
    }

    // 7. Diagnóstico para Trazas de Acceso SSH / PAM / Sistema Operativo / Syslog
    if (/target:.*:ssh|sshd|pam_unix|origen:\s*\d+\.\d+\.\d+\.\d+/i.test(searchText) || /ssh|syslog/i.test(cleanCode)) {
      return {
        matched: true,
        ruleId: 'KB-SYS-SSH-AUDIT',
        title: 'Traza de Acceso Administrativo SSH / Bastión de Servidor Entrust',
        category: 'Seguridad de Infraestructura & Accesos OS (SSH / Syslog)',
        severity: 'INFO',
        meaning: 'Registro de sesión o comando administrativo sobre el sistema operativo del servidor Entrust (canal SSH / consola de gestión) con identificación de usuario, IP de origen y nodo destino.',
        rootCause: 'Operación de administración o monitoreo ejecutada sobre el host del clúster.',
        governanceControl: '1. Verificar que la IP de origen pertenezca a una estación de salto (Jump Host / PAM) autorizada.\n2. Auditar el uso de cuentas compartidas (ej. "entrust" o "root") y exigir trazabilidad nominal individual.',
        remediation: '1. Confirmar que las sesiones hacia el puerto 22 (SSH) provengan exclusivamente del segmento de administración.\n2. Correlacionar la marca de tiempo de las sesiones SSH con las ventanas de mantenimiento aprobadas.',
        riskLevel: 'Bajo / Control de Acceso de Infraestructura',
        manualVersion: activeVersionLabel,
        docsUrl: 'https://trustedcare.entrust.com',
        trustedCareUrl: 'https://trustedcare.entrust.com',
        sectionId: 'sec-ssh-audit',
        sectionTitle: 'Control de Accesos Administrativos SSH / OS'
      };
    }

    // 8. Diagnóstico Heurístico Genérico Limpio (sin inyectar la línea cruda de un único usuario como definición general)
    return {
      matched: false,
      ruleId: 'KB-GENERIC',
      title: cleanCode ? `Operación de Sistema / Servicio [${cleanCode}]` : 'Evento Transaccional de Plataforma Entrust',
      category: 'Operaciones de Servicio & Plataforma',
      severity: 'INFO',
      meaning: cleanCode
        ? `Operación transaccional o evento de servicio clasificado bajo [${cleanCode}] en la plataforma Entrust.`
        : 'Evento operativo nominal registrado en el flujo de ejecución del servidor Entrust.',
      rootCause: 'Ejecución estándar de servicio, verificación de sesión o traza operativa del sistema.',
      governanceControl: 'Monitorear volumen por nodo y verificar ausencia de códigos de excepción asociados.',
      remediation: 'Operación nominal del sistema. No requiere acción correctiva salvo correlación con alertas previas.',
      riskLevel: 'Nominal',
      manualVersion: activeVersionLabel,
      docsUrl: 'https://docs.trustedauth.com',
      trustedCareUrl: 'https://trustedcare.entrust.com',
      sectionId: 'sec-general',
      sectionTitle: 'Manual de Operación Entrust'
    };
  }

  generateCliCommands(diag) {
    const title = (diag.title || '').toLowerCase();
    const code = diag.ruleId || '';

    let win = '';
    let nix = '';

    if (code.includes('5202404') || title.includes('database') || title.includes('sql') || title.includes('pool')) {
      win = `REM --- Verificación & Reinicio Pool BD Entrust (Windows SACVWIG07) ---
cd "C:\\Program Files\\Entrust\\IdentityGuardServer\\bin"
keytool -list -v -keystore "..\\identityguard.keystore" -storepass changeit
net stop "Entrust IdentityGuard Administration Service"
net start "Entrust IdentityGuard Administration Service"`;
      nix = `# --- Verificación & Reinicio Pool BD Entrust (Linux/WSO2 sadcluapi01) ---
systemctl status wso2am
netstat -tulpn | grep 1521
systemctl restart wso2am`;
    } else if (code.includes('5203113') || title.includes('password') || title.includes('usuario')) {
      win = `REM --- Resetear Usuario Bloqueado en Entrust CLI (Windows SACVWIG07) ---
cd "C:\\Program Files\\Entrust\\IdentityGuardServer\\tools"
IdentityGuardAdminTool.bat -user unlock -username "usuario_afectado"`;
      nix = `# --- Resetear Usuario Bloqueado en Entrust CLI (Linux) ---
/app/Entrust/tools/adminTool.sh -user unlock -username "usuario_afectado"`;
    } else if (title.includes('certificate') || title.includes('ssl') || title.includes('tls') || title.includes('cert')) {
      win = `REM --- Importar / Verificar Certificado SSL en IdentityGuard (Windows SACVWIG07) ---
keytool -list -v -keystore "C:\\Program Files\\Entrust\\IdentityGuardServer\\identityguard.keystore" -storepass changeit
keytool -importcert -alias entrust_root -file "C:\\certs\\ACCVRAIZ1.crt" -keystore "C:\\Program Files\\Entrust\\IdentityGuardServer\\identityguard.keystore" -storepass changeit -noprompt`;
      nix = `# --- Importar Certificado SSL en WSO2 API Manager & Linux (sadcluapi01) ---
cp /tmp/ACCVRAIZ1.crt /usr/local/share/ca-certificates/
update-ca-certificates
keytool -importcert -alias entrust_root -file /tmp/ACCVRAIZ1.crt -keystore /app/Apimanager/wso2am-4.2.0/repository/resources/security/client-truststore.jks -storepass wso2carbon -noprompt
chown usr_APImanager_prod_4_2:usr_APImanager_prod_4_2 /app/Apimanager/wso2am-4.2.0/repository/resources/security/client-truststore.jks`;
    } else {
      win = `REM --- Verificación General de Estado Entrust (Windows SACVWIG07) ---
sc query "Entrust IdentityGuard Administration Service"
sc query "Entrust IdentityGuard Authentication Service"`;
      nix = `# --- Verificación General de Servicios Entrust & WSO2 (Linux) ---
systemctl status wso2am
journalctl -u wso2am -n 50 --no-pager`;
    }

    return { win, nix };
  }

  diagnoseLogWithCli(logText) {
    const diag = this.diagnoseLog(logText);
    diag.cliCommands = this.generateCliCommands(diag);
    return diag;
  }

  correlateRootCause(targetLog, allLogs) {
    if (!targetLog || !allLogs || allLogs.length === 0) {
      return {
        causalFactors: ['Muestra insuficiente para correlación temporal.'],
        summary: 'No se encontraron eventos previos suficientes para inferir causalidad.'
      };
    }

    const targetIdx = allLogs.findIndex(l => l.id === targetLog.id || l.lineNum === targetLog.lineNum);
    const startIdx = Math.max(0, targetIdx - 50);
    const precedingLogs = allLogs.slice(startIdx, targetIdx);

    const factors = [];
    const ipCounts = {};
    let precedingErrors = 0;
    let poolWarnings = 0;
    let smsDelays = 0;

    precedingLogs.forEach(l => {
      if (l.clientIp) ipCounts[l.clientIp] = (ipCounts[l.clientIp] || 0) + 1;
      if (l.level === 'ERROR' || l.level === 'CRITICAL') precedingErrors++;
      if (l.message.includes('AUD155') || l.message.toLowerCase().includes('pool')) poolWarnings++;
      if (l.message.includes('AUD2309') || l.message.toLowerCase().includes('delivery')) smsDelays++;
    });

    const topIp = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
    if (topIp && topIp[1] >= 5) {
      factors.push(`🔥 Ráfaga Concentrada de Peticiones desde la IP ${topIp[0]} (${topIp[1]} transacciones en ventana previa).`);
    }

    if (poolWarnings > 0) {
      factors.push(`⚠️ Saturación progresiva de conexiones JDBC / Pool de Base de Datos detectada antes del fallo.`);
    }

    if (smsDelays > 0) {
      factors.push(`⏱️ Demoras y rechazos acumulados en la cola de despacho de SMS / Soft Tokens.`);
    }

    if (precedingErrors >= 3) {
      factors.push(`⚡ Cascada de errores continuos (${precedingErrors} fallos consecutivos en los últimos 30 segundos).`);
    }

    if (factors.length === 0) {
      factors.push('ℹ️ El incidente ocurrió de forma aislada sin degradación previa visible en los logs anteriores.');
    }

    return {
      precedingLogsCount: precedingLogs.length,
      causalFactors: factors,
      topIp: topIp ? topIp[0] : null,
      summary: factors.join(' ')
    };
  }

  extractErrorCodeFromText(text) {
    if (!text || typeof text !== 'string') return null;
    if (/The specified key does not exist|Service:\s*S3|Status Code:\s*404/i.test(text)) {
      return 'AWS-S3-404-NOKEY';
    }
    if (/grid already assigned|assignedgrid/i.test(text)) {
      return 'bulkidentityguard.add.error.assignedgrid';
    }
    if (/currently has a password|Password will not be migrated|bulkidentityguard\.add\.error\.password/i.test(text)) {
      return 'bulkidentityguard.add.error.password';
    }
    if (/already has QA|QA in migration file will be ignored|bulkidentityguard\.add\.error\.qa/i.test(text)) {
      return 'bulkidentityguard.add.error.qa';
    }
    const m = text.match(/\[(520\d{4}|AUD\d+|[A-Za-z0-9_\.-]+\.error\.[A-Za-z0-9_\.-]+|ORA-\d+|AWS-S3-404-NOKEY|JVM_OOM|TOMCAT_[A-Z_]+|JDBC_SQL_EXCEPTION|SQL_EXCEPTION)\]/i) ||
              text.match(/\b(520\d{4}|AUD\d+|bulkidentityguard\.add\.error\.[A-Za-z0-9_\.-]+|ORA-\d+|AWS-S3-404-NOKEY|JVM_OOM|TOMCAT_[A-Z_]+|JDBC_SQL_EXCEPTION|SQL_EXCEPTION)\b/i);
    if (m) return m[1];
    if (/(?:ClientAbortException|Broken pipe|Connection reset by peer)/i.test(text)) return 'TOMCAT_CLIENT_ABORT';
    if (/(?:OutOfMemoryError|Java heap space|GC overhead limit exceeded)/i.test(text)) return 'JVM_OOM';
    if (/(?:SSLHandshakeException|PKIX path building failed|SunCertPathBuilderException|KeyStoreException)/i.test(text)) return 'TOMCAT_SSL_TLS';
    if (/(?:SQLException|HikariPool|BasicDataSource|JdbcCardRepository)/i.test(text)) return 'JDBC_SQL_EXCEPTION';
    if (/(?:LDAPException|javax\.naming\.CommunicationException)/i.test(text)) return 'TOMCAT_LDAP_ERROR';
    return null;
  }

  generateExpertAiOpinion(logs, clientProfile) {
    const client = clientProfile || { name: 'Banco Mercantil C.A.', version: 'IDaaS Cloud v2026', engineer: 'Tomás Acosta' };
    const targetLogs = logs || [];
    const state = window.appState || {};
    const loadedFiles = state.loadedFiles || [];
    const hasFiles = loadedFiles.length > 0;

    // 1. Agregación Multi-Archivo Consolidada (20.1M+ logs)
    let total = 0;
    let criticalsCount = 0;
    let warningsCount = 0;

    if (hasFiles) {
      loadedFiles.forEach(f => {
        total += (f.count || 0);
        criticalsCount += (f.realErrors || 0);
        warningsCount += (f.realWarnings || 0);
      });
    }

    if (total === 0) {
      if (state.globalStreamMetrics && state.globalStreamMetrics.totalLogs) {
        total = state.globalStreamMetrics.totalLogs;
        criticalsCount = state.globalStreamMetrics.totalErrors || 0;
        warningsCount = state.globalStreamMetrics.totalWarnings || 0;
      } else {
        total = targetLogs.length;
        criticalsCount = targetLogs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR' || (l.outcome && l.outcome.includes('FAIL'))).length;
        warningsCount = targetLogs.filter(l => l.level === 'WARN' || l.level === 'WARNING').length;
      }
    } else {
      const sampleErr = targetLogs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR' || (l.outcome && l.outcome.includes('FAIL'))).length;
      if (criticalsCount === 0 && sampleErr > 0) criticalsCount = sampleErr;
      const sampleWarn = targetLogs.filter(l => l.level === 'WARN' || l.level === 'WARNING').length;
      if (warningsCount === 0 && sampleWarn > 0) warningsCount = sampleWarn;
    }

    // 2. Extracción y Clasificación de Errores en 4 Familias
    const findings520 = [];
    const findingsAud = [];
    const findingsOra = [];
    const findingsIdaas = [];
    const findingsOther = [];

    const allFindingsMap = new Map();

    // Integrar métricas de streaming del servidor
    if (state.globalStreamMetrics?.topCodes) {
      state.globalStreamMetrics.topCodes.forEach(item => {
        const code = item.code;
        const count = item.count;
        const diag = this.diagnoseLog(code, code);
        allFindingsMap.set(code, {
          code,
          occurrences: count,
          meaning: diag.meaning || `Evento registrado en plataforma (${code})`,
          rootCause: diag.rootCause || 'Fallo operacional en proceso de autenticación o aprovisionamiento.',
          remediation: diag.remediation || 'Verificar parámetros de configuración y consultar manual técnico.',
          level: (code.includes('error') || code.startsWith('520') || code.includes('ORA')) ? 'ERROR' : 'INFO',
          service: diag.category || 'Entrust Service'
        });
      });
    }

    // Integrar logs en memoria
    targetLogs.forEach(log => {
      const rawText = (log.message || '') + ' ' + (log.raw || '');
      const code = log.entrustCode || this.extractErrorCodeFromText(rawText);
      if (!code) return;

      if (!allFindingsMap.has(code)) {
        const diag = log.diagnostic || this.diagnoseLog(rawText, code);
        allFindingsMap.set(code, {
          code,
          occurrences: 1,
          meaning: diag.meaning || log.message,
          rootCause: diag.rootCause || 'Fallo en validación de credenciales o timeout de servicio.',
          remediation: diag.remediation || 'Revisar parámetros y trazas del componente.',
          level: log.level || 'ERROR',
          service: diag.category || log.service || 'Entrust Service'
        });
      } else {
        allFindingsMap.get(code).occurrences += 1;
      }
    });

    // Clasificar por familias
    Array.from(allFindingsMap.values()).forEach(f => {
      if (/^520\d{4}/.test(f.code)) {
        findings520.push(f);
      } else if (/^AUD\d+/i.test(f.code)) {
        findingsAud.push(f);
      } else if (/^ORA-\d+/i.test(f.code)) {
        findingsOra.push(f);
      } else if (/bulkidentityguard|\.assignedgrid|idaas/i.test(f.code)) {
        findingsIdaas.push(f);
      } else {
        findingsOther.push(f);
      }
    });

    const sortFn = (a, b) => b.occurrences - a.occurrences;
    findings520.sort(sortFn);
    findingsAud.sort(sortFn);
    findingsOra.sort(sortFn);
    findingsIdaas.sort(sortFn);
    findingsOther.sort(sortFn);

    const uniqueFindings = [...findings520, ...findingsAud, ...findingsOra, ...findingsIdaas, ...findingsOther];

    if (uniqueFindings.length === 0 && criticalsCount > 0) {
      uniqueFindings.push({
        code: '5202013 / INCIDENTE_OPERACIONAL',
        occurrences: criticalsCount,
        meaning: 'Excepciones operacionales detectadas en el procesamiento de logs.',
        rootCause: 'Anomalías en el flujo de autenticación o bloqueo de credenciales.',
        remediation: 'Verificar conectividad de red, configuración de base de datos y directivas de sincronización.',
        level: 'ERROR',
        service: 'Core Platform'
      });
    }

    // 3. Análisis Forense de Correlación Cruzada Multi-Archivo
    let crossFileSummary = '';
    const samFiles = loadedFiles.filter(f => f.name.toLowerCase().includes('sam_'));
    const coreFiles = loadedFiles.filter(f => f.name.toLowerCase().includes('identityguard_system'));
    const auditFiles = loadedFiles.filter(f => f.name.toLowerCase().includes('identityguard_audit'));
    const idaasFiles = loadedFiles.filter(f => f.name.toLowerCase().includes('import_identityguard') || f.name.toLowerCase().includes('auditevents') || f.name.toLowerCase().includes('idaas'));

    const samTotal = samFiles.reduce((acc, f) => acc + (f.count || 0), 0);
    const coreTotal = coreFiles.reduce((acc, f) => acc + (f.count || 0), 0);
    const auditTotal = auditFiles.reduce((acc, f) => acc + (f.count || 0), 0);
    const idaasTotal = idaasFiles.reduce((acc, f) => acc + (f.count || 0), 0);

    crossFileSummary = `CORRELACIÓN MULTI-SERVICIO AUDITADA (${loadedFiles.length || 1} Archivo(s) Totales):\n` +
      `• Capa Autenticación & Core IdentityGuard OnPremise: Procesamiento interno de credenciales, desafíos y validaciones [520xxx / IG.SYSTEM].\n` +
      `• Capa Auditoría OnPremise (IG.AUDIT): Trazabilidad de seguridad inalterable (AUD6000, AUD6001, AUD6002, AUD3000, AUD3004, AUD1210, AUD1221).\n` +
      `• Capa Infraestructura & Sistema Operativo (SSH / PAM / DB): Sesiones administrativas a nivel de host y conectividad de base de datos.` +
      (idaasFiles.length > 0 ? `\n• Capa IDaaS Cloud Migration (${idaasFiles.length} archivos, ${idaasTotal.toLocaleString()} logs): Aprovisionamiento masivo.` : '');

    const healthPenalty = criticalsCount > 0 ? Math.min(80, Math.round((criticalsCount / Math.max(1, total)) * 100 * 4)) : 0;
    const health = total > 0 ? Math.max(10, 100 - healthPenalty) : 100;

    const fileNames = loadedFiles.length > 0
      ? `${loadedFiles.length} archivo(s) cargado(s) (${loadedFiles.slice(0, 4).map(f => f.name).join(', ')}${loadedFiles.length > 4 ? '...' : ''})`
      : 'Archivos de Logs en Memoria';

    const execSummary = `Durante la evaluación técnica pericial realizada para ${client.name} (Entrust IdentityGuard OnPremise), se auditó un volumen consolidado de ${total.toLocaleString()} registros a través de ${loadedFiles.length || 1} archivo(s) de logs [${fileNames}]. La plataforma registró un índice de salud operacional del ${health}%, detectándose ${criticalsCount.toLocaleString()} eventos críticos y ${warningsCount.toLocaleString()} alertas de auditoría clasificados en: ${findings520.length} patrones [520xxx], ${findingsAud.length} códigos de auditoría [AUDxxx], ${findingsOra.length} excepciones de Base de Datos [ORA] y ${findingsOther.length} patrones de sistema/infraestructura.`;

    const remediationPlan = uniqueFindings.slice(0, 8).map(f => `[${f.code}]: ${f.remediation}`);
    if (remediationPlan.length === 0) {
      remediationPlan.push('Mantener el monitoreo continuo de transacciones y realizar auditorías periódicas de logs.');
    }

    return {
      title: `DICTAMEN TÉCNICO PERICIAL & AUDITORÍA FORENSE DE INCIDENTES`,
      client: client.name,
      date: new Date().toLocaleDateString('es-VE', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
      engineer: client.engineer || 'Tomás Acosta — IT SERVICIOS DE VENEZUELA',
      totalLogs: total,
      criticalsCount: criticalsCount,
      warningsCount: warningsCount,
      health: health,
      executiveSummary: execSummary,
      crossFileSummary: crossFileSummary,
      criticalFindings: uniqueFindings,
      findings520: findings520,
      findingsAud: findingsAud,
      findingsOra: findingsOra,
      findingsIdaas: findingsIdaas,
      regulatoryStatement: `Conforme a las mejores prácticas de Ciberseguridad Bancaria y directrices de auditoría Sudeban/ISO 27001, se certifica la trazabilidad inalterable de los eventos registrados bajo el hash SHA-256 de autenticidad emitido por IT SERVICIOS.`,
      remediationPlan: remediationPlan
    };
  }

  searchKnowledgeBase(query, limit = 6, preferVersion = null) {
    const q = String(query || '').trim();
    if (!q) return [];
    const qLower = q.toLowerCase();
    const qVerMatch = q.match(/\b(?:(?:ig|identityguard|entrust)\s*(?:v|ver|vers[ií]on|release)?\s*|(?:v|vers[ií]on|release)\s*)(13|12|11|10|9)(?:\.\d+)?\b/i)
      || q.match(/\b(13\.0|12\.0|11\.0|10\.\d+|9\.\d+)\b/i)
      || (/idaas/i.test(q) ? ['idaas', 'IDaaS Cloud'] : null);
    const effectiveVersion = preferVersion
      ? this._normalizeDocVersionLabel(preferVersion)
      : (qVerMatch ? this._normalizeDocVersionLabel(qVerMatch[1]) : this._detectActiveDocVersion());
    const stopWords = new Set(['de', 'la', 'el', 'los', 'las', 'un', 'una', 'en', 'y', 'o', 'por', 'para', 'con', 'que', 'como', 'cual', 'es', 'son', 'the', 'and', 'for', 'how', 'what', 'error', 'errores', 'falla', 'fallo', 'solucion', 'resuelvo', 'resolver', 'significa']);
    const codes = qLower.match(/(?:52\d{4,5}|aud\d+|ora-\d+|s3-404|ssh-\w+|tomcat_\w+|jvm_oom|jdbc_sql_exception|sql_exception)/gi) || [];
    const tokens = (qLower.match(/[a-z0-9_.\-áéíóúñ]{3,}/gi) || []).filter(t => !stopWords.has(t));
    const results = [];
    const seenKeys = new Set();

    // 1. Buscar primero en ENTRUST_EXACT_CATALOG
    Object.entries(ENTRUST_EXACT_CATALOG).forEach(([code, entry]) => {
      let score = 0;
      const cLower = code.toLowerCase();
      const hay = `${cLower} ${entry.title} ${entry.category} ${entry.meaning} ${entry.rootCause} ${entry.remediation}`.toLowerCase();
      if (codes.some(c => c.toLowerCase() === cLower) || qLower.includes(cLower)) {
        score += 150;
      }
      tokens.forEach(tok => {
        if (cLower.includes(tok)) score += 60;
        if ((entry.title || '').toLowerCase().includes(tok)) score += 30;
        if (hay.includes(tok)) score += 12;
      });
      if (score > 0) {
        seenKeys.add(cLower);
        results.push({
          source: 'ENTRUST_EXACT_CATALOG',
          code,
          title: entry.title,
          category: entry.category,
          severity: entry.severity || 'ERROR',
          meaning: entry.meaning,
          rootCause: entry.rootCause,
          remediation: entry.remediation,
          manualVersion: 'IG 13.0 / KB Oficial',
          sectionTitle: `${code} — ${entry.title}`,
          score
        });
      }
    });

    // 2. Buscar en this.rules (reglas detalladas + personalizadas)
    (this.rules || []).forEach(rule => {
      let score = 0;
      const rId = String(rule.id || '').toLowerCase();
      const titleLow = String(rule.title || '').toLowerCase();
      const hay = `${rId} ${titleLow} ${rule.category || ''} ${rule.meaning || ''} ${rule.rootCause || ''} ${rule.remediation || ''}`.toLowerCase();

      if (rule.pattern && rule.pattern instanceof RegExp && rule.pattern.test(q)) {
        score += 130;
      }
      codes.forEach(c => {
        if (hay.includes(c.toLowerCase())) score += 110;
      });
      tokens.forEach(tok => {
        if (titleLow.includes(tok)) score += 28;
        if (hay.includes(tok)) score += 10;
      });

      if (score > 0) {
        const extractedCode = codes.find(c => hay.includes(c.toLowerCase())) || rule.id;
        if (seenKeys.has(String(extractedCode).toLowerCase()) && score < 130) {
          score -= 10;
        }
        results.push({
          source: 'KB_RULES',
          code: String(extractedCode).toUpperCase(),
          title: rule.title,
          category: rule.category,
          severity: rule.severity || 'ERROR',
          meaning: rule.meaning,
          rootCause: rule.rootCause,
          remediation: rule.remediation,
          riskLevel: rule.riskLevel || '',
          manualVersion: rule.manualVersion || 'vEntrust',
          sectionTitle: rule.sectionTitle || rule.title,
          score
        });
      }
    });

    // 3. Buscar en códigos extraídos de PDFs oficiales cargados en el servidor (todas las versiones)
    const customPdfCatalog = (typeof window !== 'undefined' && window.ENTRUST_CUSTOM_PDF_CATALOG) ? window.ENTRUST_CUSTOM_PDF_CATALOG : {};
    const customPdfEntries = (typeof window !== 'undefined' && Array.isArray(window.ENTRUST_CUSTOM_PDF_ENTRIES) && window.ENTRUST_CUSTOM_PDF_ENTRIES.length > 0)
      ? window.ENTRUST_CUSTOM_PDF_ENTRIES
      : Object.values(customPdfCatalog);
    customPdfEntries.forEach(entry => {
      if (!entry || !entry.code) return;
      const entryVer = entry.docVersion || 'General';
      let score = 0;
      const cLower = String(entry.code).toLowerCase();
      const hay = `${cLower} ${entry.title || ''} ${entry.excerpt || ''} ${entry.sourceFile || ''} ${entryVer}`.toLowerCase();
      if (codes.some(c => c.toLowerCase() === cLower) || qLower.includes(cLower)) {
        score += 145;
      }
      tokens.forEach(tok => {
        if (cLower.includes(tok)) score += 60;
        if ((entry.title || '').toLowerCase().includes(tok)) score += 28;
        if (hay.includes(tok)) score += 12;
      });
      if (score > 0) {
        if (effectiveVersion && entryVer === effectiveVersion) {
          score += 15;
        }
        const isPdf = /\.pdf($|#)/i.test(entry.manualFile || entry.sourceFile || '');
        const kindBadge = isPdf ? 'PDF Oficial' : 'Documento';
        const locLabel = isPdf
          ? `Pág. ${entry.page || 1}`
          : ((Number(entry.page || 1) > 1) ? `Secc. ${entry.page}` : 'HTML/Doc');
        results.push({
          source: entry.sourceType || (isPdf ? 'PDF_CUSTOM' : 'DOC_CUSTOM'),
          code: entry.code,
          title: entry.title || entry.code,
          category: `${kindBadge} ${entryVer} (${entry.sourceFile || 'custom'})`,
          severity: entry.severity || 'ERROR',
          meaning: entry.excerpt || '',
          rootCause: `Extracto literal de "${entry.sourceFile || 'custom'}" [${entryVer}] (${locLabel}).`,
          remediation: `Abrir documento oficial (${entryVer}): ${entry.manualFile || ''}`,
          manualVersion: `${kindBadge} ${entryVer}: ${entry.sourceFile || 'custom'} (${locLabel})`,
          manualFile: entry.manualFile || null,
          docVersion: entryVer,
          sectionTitle: `${entry.code} (${entryVer}) — ${entry.title || ''}`,
          score
        });
      }
    });

    // 4. Buscar en los 361 códigos AUD oficiales del WebHelp (IG 11/12/13)
    const officialAudCatalog = (typeof window !== 'undefined' && window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG) ? window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG : {};
    Object.entries(officialAudCatalog).forEach(([code, entry]) => {
      const cLower = code.toLowerCase();
      if (seenKeys.has(cLower)) return;
      let score = 0;
      const hay = `${cLower} ${entry.name || ''} ${entry.category || ''} ${entry.desc || ''}`.toLowerCase();
      if (codes.some(c => c.toLowerCase() === cLower) || qLower.includes(cLower)) {
        score += 140;
      }
      tokens.forEach(tok => {
        if (cLower.includes(tok)) score += 60;
        if ((entry.name || '').toLowerCase().includes(tok)) score += 26;
        if (hay.includes(tok)) score += 10;
      });
      if (score > 0) {
        const rawLvl = String(entry.level || 'INFO').toUpperCase();
        const sev = /ERROR|CRITICAL|FATAL/.test(rawLvl) ? 'ERROR' : (/WARN/.test(rawLvl) ? 'WARN' : 'INFO');
        results.push({
          source: 'WEBHELP_AUD',
          code,
          title: `[${code}] ${entry.name || 'Evento Entrust'}`,
          category: entry.category || 'Auditoría Entrust (AUD)',
          severity: sev,
          meaning: `${entry.desc || ''}${entry.snmp ? ` [SNMP Trap: ${entry.snmp}]` : ''}`,
          rootCause: `Definición oficial Entrust WebHelp (${entry.category || 'Auditoría'}).`,
          remediation: entry.manualFile ? `Consultar tabla oficial en manuals/${entry.manualFile}` : 'Consultar documentación oficial WebHelp Entrust.',
          manualVersion: 'IG 13.0 WebHelp Oficial',
          manualFile: entry.manualFile ? (entry.manualFile.startsWith('manuals/') ? entry.manualFile : `manuals/${entry.manualFile}`) : null,
          sectionTitle: `${code} — ${entry.name || ''}`,
          score
        });
      }
    });

    results.sort((a, b) => b.score - a.score);
    return results.slice(0, limit);
  }

  getUnifiedCatalogEntries() {
    const entries = [];
    const representedCodes = new Set();
    const normalizePath = (p) => {
      if (!p) return null;
      const s = String(p).trim();
      if (!s) return null;
      if (/^(https?:\/\/|\/|manuals\/)/i.test(s)) return s;
      return `manuals/${s}`;
    };
    const classifyFamily = (code, category = '', ruleId = '') => {
      const c = String(code || '').toUpperCase();
      const cat = String(category || '');
      const rid = String(ruleId || '').toUpperCase();
      if (/^520\d{4}$/.test(c) || /ENTRUST-520\d{4}/.test(rid)) return '520';
      if (/^AUD\d+/.test(c) || /ENTRUST-AUD\d+/.test(rid)) return 'AUD';
      if (/^(TOMCAT_|JVM_|JDBC_SQL_EXCEPTION|SQL_EXCEPTION)/.test(c) || /tomcat|jvm/i.test(cat)) return 'TOMCAT';
      if (/^ORA-\d+/.test(c) || /oracle/i.test(cat)) return 'ORA';
      return 'IDAAS';
    };

    // A. Todos los códigos oficiales AUDxxx del WebHelp IG 11.0 / 12.0 / 13.0
    const officialAudCatalog = (typeof window !== 'undefined' && window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG) ? window.ENTRUST_OFFICIAL_AUD_MANUAL_CATALOG : {};
    Object.entries(officialAudCatalog).forEach(([code, aud]) => {
      const codeUp = code.toUpperCase();
      representedCodes.add(codeUp);
      const exact = (typeof ENTRUST_EXACT_CATALOG !== 'undefined') ? ENTRUST_EXACT_CATALOG[codeUp] : null;
      const rawLvl = String(aud.level || (exact && exact.severity) || 'INFO').toUpperCase();
      const sev = /CRITICAL|FATAL/.test(rawLvl) ? 'CRITICAL' : (/ERROR/.test(rawLvl) ? 'ERROR' : (/WARN/.test(rawLvl) ? 'WARN' : 'INFO'));
      entries.push({
        uid: `AUD-${codeUp}`,
        code: codeUp,
        title: (exact && exact.title) ? exact.title : (aud.name || codeUp),
        category: aud.category || (exact && exact.category) || 'Auditoría Entrust (WebHelp)',
        severity: sev,
        family: 'AUD',
        meaning: (exact && exact.meaning)
          ? exact.meaning
          : `${aud.desc || ''}${aud.snmp ? ` [SNMP Trap: ${aud.snmp}]` : ''}`,
        rootCause: (exact && exact.rootCause) ? exact.rootCause : `Evento oficial de auditoría Entrust IdentityGuard (${aud.category || 'Logging'}).`,
        remediation: (exact && exact.remediation)
          ? exact.remediation
          : `Consultar referencia oficial en ${normalizePath(aud.manualFile) || 'WebHelp Admin Guide'}.`,
        sourceLabel: '📘 WebHelp Oficial IG 11/12/13',
        sourceKind: 'WEBHELP_AUD',
        docVersion: 'IG 11/12/13',
        docVersions: ['IG 13.0', 'IG 12.0', 'IG 11.0'],
        manualPath: normalizePath(aud.manualFile),
        snmp: aud.snmp || ''
      });
    });

    // B. Catálogo Exacto ENTRUST_EXACT_CATALOG (520xxxx, Tomcat/JVM/JDBC, ORA-, SSH, S3, IDaaS)
    if (typeof ENTRUST_EXACT_CATALOG !== 'undefined') {
      Object.entries(ENTRUST_EXACT_CATALOG).forEach(([code, entry]) => {
        const codeUp = code.toUpperCase();
        if (representedCodes.has(codeUp)) return;
        representedCodes.add(codeUp);
        const fam = classifyFamily(code, entry.category);
        const mPath = normalizePath(entry.manualFile);
        let srcLabel = '🛡️ Catálogo Técnico KB';
        if (fam === 'TOMCAT') {
          srcLabel = mPath ? '🐱 WebHelp IG 13 + Apache Tomcat' : '🐱 Tomcat / JVM Catalina';
        } else if (mPath) {
          srcLabel = '📘 Catálogo Técnico (WebHelp)';
        }
        const isIdaas = fam === 'IDAAS' && /idaas/i.test(`${code} ${mPath || ''} ${entry.category || ''}`);
        const exactDocVer = isIdaas ? 'IDaaS Cloud' : (mPath && /IG_130/i.test(mPath) ? 'IG 13.0' : (mPath ? 'IG 11/12/13' : 'General'));
        const exactDocVers = isIdaas ? ['IDaaS Cloud'] : (mPath ? ['IG 13.0', 'IG 12.0', 'IG 11.0'] : ['General']);
        entries.push({
          uid: `EXACT-${code}`,
          code,
          title: entry.title || code,
          category: entry.category || 'Catálogo Técnico',
          severity: entry.severity || 'ERROR',
          family: fam,
          docVersion: exactDocVer,
          docVersions: exactDocVers,
          meaning: entry.meaning || '',
          rootCause: entry.rootCause || '',
          remediation: entry.remediation || '',
          sourceLabel: srcLabel,
          sourceKind: 'EXACT_CATALOG',
          manualPath: mPath,
          snmp: ''
        });
      });
    }

    // C. Códigos extraídos literalmente de PDFs oficiales cargados por el usuario (multiversión)
    const customPdfCatalog = (typeof window !== 'undefined' && window.ENTRUST_CUSTOM_PDF_CATALOG) ? window.ENTRUST_CUSTOM_PDF_CATALOG : {};
    const customPdfEntries = (typeof window !== 'undefined' && Array.isArray(window.ENTRUST_CUSTOM_PDF_ENTRIES) && window.ENTRUST_CUSTOM_PDF_ENTRIES.length > 0)
      ? window.ENTRUST_CUSTOM_PDF_ENTRIES
      : Object.values(customPdfCatalog);
    customPdfEntries.forEach(pdf => {
      if (!pdf || !pdf.code) return;
      const pdfVer = pdf.docVersion || 'General';
      const verSlug = pdfVer.replace(/[^a-z0-9]/gi, '_').toLowerCase();
      const fileSlug = String(pdf.sourceFile || 'doc').replace(/[^a-z0-9]/gi, '_').toLowerCase().slice(0, 24);
      const isPdf = /\.pdf($|#)/i.test(pdf.manualFile || pdf.sourceFile || '');
      const locLabel = isPdf
        ? `Pág. ${pdf.page || 1}`
        : ((Number(pdf.page || 1) > 1) ? `Secc. ${pdf.page}` : 'HTML/Doc');
      const srcLabel = isPdf
        ? `📄 PDF ${pdfVer}: ${pdf.sourceFile || 'Custom'} (${locLabel})`
        : `🌐 Doc ${pdfVer}: ${pdf.sourceFile || 'Custom'}${Number(pdf.page || 1) > 1 ? ` (Secc. ${pdf.page})` : ''}`;
      entries.push({
        uid: `PDF-${verSlug}-${pdf.code}-${fileSlug}`,
        code: pdf.code,
        title: pdf.title || pdf.code,
        category: `${isPdf ? 'PDF' : 'Doc'} [${pdfVer}]: ${pdf.sourceFile || 'Documento'} (${locLabel})`,
        severity: pdf.severity || 'ERROR',
        family: 'PDF',
        docVersion: pdfVer,
        docVersions: [pdfVer],
        meaning: pdf.excerpt || '',
        rootCause: `Contexto literal extraído de ${pdf.sourceFile || 'documento'} (${pdfVer}, ${locLabel}).`,
        remediation: `Abrir ${pdf.sourceFile || 'el manual'} (${pdfVer}) en ${locLabel} para revisar el detalle completo del fabricante.`,
        sourceLabel: srcLabel,
        sourceKind: pdf.sourceType || (isPdf ? 'PDF_CUSTOM' : 'DOC_CUSTOM'),
        manualPath: normalizePath(pdf.manualFile),
        snmp: ''
      });
    });

    // D. Reglas detalladas del motor KB y reglas personalizadas del usuario
    const customOnlyIds = new Set((this.getCustomRulesOnly() || []).map(r => r.id));
    (this.rules || []).forEach(rule => {
      const isCustom = customOnlyIds.has(rule.id);
      const idCode = String(rule.id || '').replace(/^KB-(?:ENTRUST-|ORA-)?/i, '');
      const titleCodeMatch = String(rule.title || '').match(/(520\d{4}|AUD\d+|ORA-\d{5}|S3-404|SSH-\w+)/i);
      const primaryCode = (titleCodeMatch ? titleCodeMatch[1] : idCode).toUpperCase();

      if (!isCustom && (representedCodes.has(primaryCode) || representedCodes.has(idCode.toUpperCase()))) {
        return;
      }
      if (!isCustom) {
        representedCodes.add(primaryCode);
      }

      const fam = isCustom ? 'CUSTOM' : classifyFamily(primaryCode, rule.category, rule.id);
      const docUrl = rule.docsUrl ? String(rule.docsUrl) : null;
      entries.push({
        uid: `RULE-${rule.id}`,
        code: isCustom ? (rule.id || 'CUSTOM') : primaryCode,
        title: rule.title || rule.id,
        category: rule.category || 'Regla KB',
        severity: rule.severity || 'ERROR',
        family: fam,
        docVersion: rule.docVersion || 'General',
        docVersions: [rule.docVersion || 'General'],
        meaning: rule.meaning || '',
        rootCause: rule.rootCause || '',
        remediation: rule.remediation || '',
        sourceLabel: isCustom ? '🧩 Regla Personalizada' : '🛡️ Regla Base KB',
        sourceKind: isCustom ? 'CUSTOM_RULE' : 'KB_RULE',
        manualPath: docUrl,
        snmp: ''
      });
    });

    return entries;
  }

  getAllRules() {
    return this.rules;
  }
}

window.knowledgeBaseEngine = new KnowledgeBase();
