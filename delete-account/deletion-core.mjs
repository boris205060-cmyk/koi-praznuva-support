export class AccountDeletionError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = 'AccountDeletionError';
    this.code = code;
  }
}

export function isConfiguredFirebaseWebApp(config) {
  return Boolean(
    config &&
      config.apiKey &&
      config.appId &&
      config.authDomain === 'koi-praznuva.firebaseapp.com' &&
      config.projectId === 'koi-praznuva',
  );
}

export async function deleteAuthenticatedAccount({
  user,
  providerId,
  reauthenticate,
  deleteCloudData,
  revokeAppleToken,
  deleteAuthUser,
  onProgress = () => {},
}) {
  if (!user?.uid) {
    throw new AccountDeletionError(
      'not-authenticated',
      'Няма удостоверен акаунт за изтриване.',
    );
  }

  const expectedUid = user.uid;
  onProgress('reauthenticating');
  const reauthResult = await reauthenticate();
  const verifiedUser = reauthResult?.user;
  if (!verifiedUser?.uid || verifiedUser.uid !== expectedUid) {
    throw new AccountDeletionError(
      'account-mismatch',
      'Избраният профил не съвпада с акаунта за изтриване.',
    );
  }

  onProgress('deleting-cloud-data');
  await deleteCloudData(expectedUid);

  if (providerId === 'apple.com') {
    const accessToken = reauthResult?.accessToken;
    if (!accessToken) {
      throw new AccountDeletionError(
        'apple-token-missing',
        'Apple не върна токен за отмяна на достъпа. Опитай входа отново.',
      );
    }
    onProgress('revoking-apple-token');
    await revokeAppleToken(accessToken);
  }

  onProgress('deleting-auth-user');
  await deleteAuthUser(verifiedUser);
  onProgress('complete');
}
