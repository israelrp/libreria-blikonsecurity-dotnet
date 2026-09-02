# Permissions

## 1. Definición

Permissions es el plano administrativo (lugar donde se configura el modelo de
autorización) en el que se definen sistemas, scopes, permisos y roles. Security
utiliza esa configuración para administrar asignaciones y emitir JWT con los
permisos efectivos de cada principal.

Permissions no autentica una llamada HTTP. Define qué capacidades existen y
cómo se agrupan; Security y la API consumidora aplican esas decisiones.

## 2. Modelo conceptual

```text
Sistema
|-- Scopes
|   `-- Permisos
|-- Roles
|   `-- Permisos seleccionados de uno o varios scopes
`-- Asignaciones
    `-- Principal + recurso concreto/customKey + rol
```

Un principal es la identidad que recibe autorización, como un usuario o sistema.

| Concepto | Pregunta que responde | Ejemplo |
| --- | --- | --- |
| Sistema | ¿Quién define y posee los permisos? | Developer Accounts |
| Scope | ¿En qué dominio funcional está la capacidad? | `users` |
| Permiso | ¿Qué operación se permite? | `users.write` |
| Rol | ¿Qué conjunto de capacidades recibe alguien? | `developer` |
| `customKey` | ¿Sobre qué instancia concreta recibe el rol? | `dev-account.123` |

## 3. Cómo definir un scope

Un scope es un dominio funcional o espacio de nombres (agrupación que evita
ambigüedades entre identificadores) que reúne permisos relacionados con una
misma entidad, área o responsabilidad dentro de un sistema.

Descripción breve recomendada para la interfaz:

> Agrupa los permisos relacionados con un área funcional del sistema.

El scope representa qué área funcional se protege; no representa directamente
la instancia concreta hacia la que apunta una asignación.

El permiso completo sigue esta estructura:

```text
<scope>.<acción>
```

```text
Scope:    users
Acción:   write
Permiso:  users.write
```

## 4. Ejemplo de Blikon

```text
clientauth
|-- read
`-- send

user
|-- update
`-- write
```

Los permisos completos son:

```text
clientauth.read
clientauth.send
user.update
user.write
```

- `clientauth` es el dominio funcional relacionado con autenticación.
- `send` es una acción permitida dentro de ese dominio.
- `clientauth.send` es la capacidad efectiva.

El rol `security-entity` agrupa:

```text
security-entity
|-- clientauth.read
|-- clientauth.send
|-- user.update
`-- user.write
```

## 5. Ejemplo de Developer Accounts

```text
account
|-- changename
|-- changeicon
`-- read

users
|-- write
|-- read
`-- delete

develop
|-- is-developer
`-- write

designer
`-- plugin-publish
```

Los permisos completos incluyen:

```text
account.changename
account.changeicon
account.read
users.write
users.read
users.delete
develop.is-developer
develop.write
designer.plugin-publish
```

## 6. Roles y asignación de permisos

Un rol agrupa permisos de uno o varios scopes. Por ejemplo:

```text
developer
|-- account.read
|-- users.read
|-- users.write
|-- develop.write
`-- develop.is-developer
```

```text
member
|-- account.read
|-- develop.is-developer
`-- develop.write
```

El rol `owner` puede recibir todos los permisos seleccionados de varios scopes:

```text
owner
|-- todos los permisos de account
|-- todos los permisos de users
`-- todos los permisos de develop
```

El rol `system`, usado para comunicación sistema a sistema, puede recibir solo
los permisos administrativos necesarios, por ejemplo los de `users`.

En la matriz de Permissions:

- Las filas son permisos agrupados por scope.
- Las columnas son roles.
- Cada selección relaciona un permiso con un rol.
- Seleccionar el encabezado de un scope asigna sus permisos al rol.

## 7. Seleccionar un scope no crea un wildcard

Seleccionar un scope completo en Permissions relaciona sus permisos actuales
con el rol. No significa que `Security.Auth.dll` acepte `users.*`.

La DLL compara cadenas exactas:

```text
users.read
users.write
users.delete
```

Security debe materializar cada permiso efectivo en el JWT. Si se agrega uno
nuevo, debe confirmarse si los roles que tenían el scope completo lo heredan y
cuándo aparece en tokens nuevos.

La DLL tampoco autoriza por el nombre del rol. Permissions y Security resuelven
los roles; `SecureAuth` evalúa audiences, `customKey` y permisos efectivos.

## 8. Scope frente a `customKey`

Esta es la separación principal:

```text
scope     = users
permiso   = users.write
customKey = dev-account.123
```

`users` clasifica la capacidad como una operación relacionada con usuarios. No
identifica la Developer Account `123`; la `customKey` sí delimita esa instancia:

```text
Usuario U1
`-- rol developer
    `-- sobre dev-account.123
```

El mismo usuario puede no tener acceso sobre `dev-account.456`, aunque el rol
`developer` incluya `users.write`.

## 9. Scope administrativo frente al claim `scp`

El nombre `scp` puede confundir porque su segundo nivel usa la `customKey`, no el
scope administrativo:

```json
{
  "scp": {
    "<developer-system-id>": {
      "dev-account.123": [
        "account.read",
        "users.read",
        "users.write"
      ]
    }
  }
}
```

```text
<developer-system-id> = propietario de los permisos
dev-account.123       = customKey o frontera de asignación
users                 = scope administrativo
users.write           = permiso efectivo
```

## 10. Definir un rol no concede acceso

El catálogo solo establece qué permisos contiene el rol. Security debe asignarlo
a un principal sobre una `customKey`:

```text
Principal:       usuario U1
Sistema destino: Developer Accounts
customKey:       dev-account.123
Rol:             developer
```

```text
U1 + dev-account.123 + developer
                     |-- account.read
                     |-- users.read
                     |-- users.write
                     |-- develop.write
                     `-- develop.is-developer
```

Una instancia no extiende acceso a otra:

```text
U1 + dev-account.123 + developer -> users.write concedido
U1 + dev-account.456 + sin rol    -> users.write denegado
```

## 11. Correspondencia con `SecureAuth`

```csharp
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "users.write")]
```

Solicita:

```text
Propietario: developer-system
Instancia:   dev-account.{accountId}
Capacidad:   users.write
```

La evaluación conceptual es:

```text
¿El JWT incluye la audience del propietario?
¿scp contiene ese sistema?
¿Existe la customKey dev-account.{accountId}?
¿Esa customKey contiene users.write?
```

El permiso puede proceder de cualquier rol; la DLL no necesita conocerlo.

## 12. Flujo completo

```text
1. Permissions define:
   users -> users.write -> developer

2. Security asigna:
   U1 -> dev-account.123 -> developer

3. Security resuelve:
   developer -> users.write y otros permisos

4. Security emite un JWT actualizado.

5. El cliente envía Authorization: Bearer <JWT>.

6. Security.Auth valida el token.

7. SecureAuth exige:
   dev-account.123 + users.write

8. El endpoint se autoriza o devuelve 403.
```

Después de cambiar un rol o asignación debe renovarse el JWT.

## 13. Condiciones para que un permiso funcione

1. El sistema debe existir en Permissions.
2. El scope debe pertenecer al sistema correcto.
3. El permiso debe existir dentro del scope.
4. El rol debe contener ese permiso.
5. El principal debe tener el rol sobre la `customKey` correcta.
6. La asignación debe usar el sistema propietario correcto.
7. Security debe emitir o renovar el JWT después de la asignación.
8. El JWT debe incluir la audience del propietario.
9. `scp` debe incluir la `customKey` y el permiso efectivo.
10. La API debe configurar el propietario externo en `ScopeOwners`.
11. `SecureAuth` debe pedir la misma `customKey` y permiso.
12. Sus placeholders deben resolverse desde route, query o body raíz.

```text
Asignación: dev-account.123 -> users.write
Endpoint:   dev-account.456 -> users.write
Resultado:  403 Forbidden
```

## 14. Recomendación de nomenclatura

Se recomiendan sustantivos o dominios funcionales para scopes y acciones claras
para permisos:

```text
accounts.read
accounts.rename
accounts.change-icon

users.read
users.add
users.remove

authentication.send-code
authentication.validate-code

plugins.publish
```

Cada permiso debe leerse como:

```text
<recurso o dominio>.<acción autorizada>
```

### Evitar acciones ambiguas

`user.update` y `user.write` pueden solaparse. Si ambos permanecen, necesitan una
diferencia verificable, por ejemplo:

```text
user.update-profile = modifica nombre y fotografía
user.write-settings = modifica configuración operativa
```

Si no existe esa diferencia, conviene conservar uno solo.

### Evitar confundir capacidades con atributos

`develop.is-developer` parece un estado de identidad. Puede ser válido si
habilita una operación, pero debe documentarse cuál. Si solo afirma que alguien
es desarrollador, podría ser un rol o atributo en vez de permiso.

### Mantener consistencia gramatical

```text
accounts.rename       recomendado
account.changename    menos consistente
```

La forma existente puede conservarse por compatibilidad, pero mezclar criterios
dificulta descubrir permisos y evitar duplicados.

## 15. Riesgos

### Scopes demasiado amplios

Un scope como `system` puede concentrar capacidades sin relación, dificultar su
revisión y aumentar el impacto de una asignación incorrecta.

### Scopes demasiado específicos

Un scope por endpoint produce fragmentación y acoplamiento fuerte (cuando dos
componentes dependen demasiado de su estructura). Deben representar dominios
estables, no rutas HTTP.

### Permisos redundantes

Acciones similares como `update`, `write` y `edit` pueden usarse de manera
inconsistente o conceder capacidades inesperadas.

### Roles excesivamente poderosos

Asignar scopes completos facilita la administración, pero puede violar el
principio de mínimo privilegio (conceder solo el acceso necesario).

### Herencia accidental

Si un rol hereda automáticamente permisos nuevos de un scope completo, agregar
una capacidad puede ampliar acceso sin revisión. Debe confirmarse el
comportamiento y establecer aprobación explícita.

### `customKey` inconsistente

Estas variantes pueden representar recursos distintos por accidente:

```text
dev-account.123
developer-account.123
dev-account-123
```

Cada recurso necesita una sola convención.

### Tokens desactualizados

Los cambios no modifican tokens ya emitidos. Debe definirse su renovación,
expiración y tiempo de permanencia de permisos revocados.

### Roles locales no sincronizados

Un rol local no equivale a un rol de Permissions. Si ambos representan la misma
decisión, el flujo necesita sincronización, idempotencia (repetir una operación
no cambia el resultado después de la primera) y compensación.

## 16. Lista para diseñar un permiso

1. ¿Qué operación de negocio habilita exactamente?
2. ¿A qué dominio funcional pertenece?
3. ¿Existe otro permiso con el mismo significado?
4. ¿El nombre se lee como `<scope>.<acción>`?
5. ¿Qué roles deben recibirlo?
6. ¿Se aplica globalmente o por instancia?
7. ¿Cuál es la convención de `customKey`?
8. ¿Qué sistema es propietario?
9. ¿Qué APIs deben incluirlo en `ScopeOwners`?
10. ¿Qué sucede con roles que ya tienen el scope completo?
11. ¿Cómo se asignará y revocará?
12. ¿Cómo renovará el usuario su JWT?
13. ¿Qué casos de `401` y `403` deben probarse?

Toda autorización debe poder expresarse sin ambigüedad como:

```text
principal + sistema propietario + customKey + permiso efectivo
```
