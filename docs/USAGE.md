## Auth API
To use the API, make an instance of the [auth.ts](src/modules/user/models/auth.ts) class. Interface methods are available in the class.

### Example of creating a role:
```typescript
const auth = new Auth();

await auth.createRole('Commenter');
```


### Example of assigning permissions to a role:
```typescript
const auth = new Auth();

await auth.addPermissionsToRole('Commenter', [ {
  permission_id: Permission.TRANSPORT,
  read: PermissionLevel.OWN,
  write: PermissionLevel.NONE,
  execute: PermissionLevel.NONE,
}]);
```
do note that the permissions and role must already exist for this to work. Available permissions can be found and added in [permissions.ts](src/config/permissions.ts). Same goes for permission levels.

### Example of removing permissions from a role:
```typescript
const auth = new Auth();

await auth.removePermissionsFromRole('Commenter', [Permission.TRANSPORT]);
```
do note that you should provide at least 1 valid, existing and present permission in the array, else the function returns `false`, indicating a failure.


### Example of granting roles to a user:
```typescript
const auth = new Auth();

await auth.grantRoles(["Commenter", "Gardener"]);
// or
await auth.grantRoles(["Mayor", "Director"], userId);
```
where `userId` is the ID of the user you wish to provide the roles to.
If no ID is provided to the function, it attempts to use the user attached to the context, provided there is one. Keep in mind the roles need to exist for them to be grantable to the user.


### Example of checking whether a user has access to a resource:
```typescript
const auth = new Auth();

// auth.canAccess(userId, PermissionPass[]): Promise<boolean>
await auth.canAccess(123, [
  {
    permission: Permission.TRANSPORT,
    type: PermissionType.EXECUTE,
    level: PermissionLevel.OWN
  }, {
    permission: Permission.TRANSPORT_STATE,
    type: PermissionType.READ,
    level: PermissionLevel.OWN
  }, {
    permission: Permission.TRANSPORT_STATE,
    type: PermissionType.WRITE,
    level: PermissionLevel.OWN
  }
]);
```
Returns `true` if user has a role with a permission that can access the provided resource with the required actions. The function checks whether the user has the permissions with the fitting permission and type, while the level needs to be equal or greater than the one provided the arguments.


### Example of generating a JWT token
```typescript
const auth = new Auth();

const token = await auth.generateToken(payload, subject, userId?, exp?);
```
Generates a JWT token. `payload` is the data you want it to contain, `subject` should be a value from `JwtTokenType`, which can be found in [auth-mysql.ts](src/models/auth-mysql.ts). `userId` is optional and indicates which user a token pertains to, and `exp` is the time to expiration, which defaults to `'1d'`.

### Example of validating a JWT token
```typescript
const auth = new Auth();

const isValid = await auth.validateToken(token);
```
Checks whether a token can be successfully decoded, is present in the database, has not yet been invalidated and has not yet expired. Returns `true` if all these conditions are met.

### TODO: More examples