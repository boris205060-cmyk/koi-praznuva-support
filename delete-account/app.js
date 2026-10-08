import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-app.js';
import {
  FacebookAuthProvider,
  GoogleAuthProvider,
  OAuthProvider,
  deleteUser,
  getAdditionalUserInfo,
  getAuth,
  onAuthStateChanged,
  reauthenticateWithPopup,
  revokeAccessToken,
  signInWithPopup,
  signOut,
} from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-auth.js';
import {
  collection,
  deleteDoc,
  doc,
  getDocs,
  getFirestore,
  limit,
  query,
  writeBatch,
} from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-firestore.js';

import { firebaseConfig } from './firebase-config.js';
import {
  AccountDeletionError,
  deleteAuthenticatedAccount,
  isConfiguredFirebaseWebApp,
} from './deletion-core.mjs';

const stateIds = [
  'setup-state',
  'signin-state',
  'confirm-state',
  'progress-state',
  'success-state',
  'error-state',
];
const elements = Object.fromEntries(
  stateIds.map((id) => [id, document.getElementById(id)]),
);
const confirmation = document.getElementById('delete-confirmation');
const deleteAction = document.getElementById('delete-action');
const errorMessage = document.getElementById('error-message');
const progressMessage = document.getElementById('progress-message');

function showState(id) {
  for (const stateId of stateIds) {
    elements[stateId].hidden = stateId !== id;
  }
}

if (!isConfiguredFirebaseWebApp(firebaseConfig)) {
  showState('setup-state');
} else {
  startDeletionApp();
}

function startDeletionApp() {
  const firebaseApp = initializeApp(firebaseConfig);
  const auth = getAuth(firebaseApp);
  const firestore = getFirestore(firebaseApp);
  let selectedProvider = null;
  let busy = false;

  const providers = {
    google: new GoogleAuthProvider(),
    facebook: new FacebookAuthProvider(),
    apple: new OAuthProvider('apple.com'),
  };
  providers.google.setCustomParameters({ prompt: 'select_account' });
  providers.facebook.setCustomParameters({ auth_type: 'reauthorize' });
  providers.apple.addScope('email');
  providers.apple.addScope('name');

  const providerLabels = {
    'google.com': 'Google',
    'facebook.com': 'Facebook',
    'apple.com': 'Apple',
  };

  function providerForUser(user) {
    const providerId = user?.providerData
      ?.map((entry) => entry.providerId)
      .find((id) => providerLabels[id]);
    if (!providerId) return null;
    return {
      id: providerId,
      instance:
        providerId === 'google.com'
          ? providers.google
          : providerId === 'facebook.com'
            ? providers.facebook
            : providers.apple,
    };
  }

  function showAccount(user) {
    const linkedProviderIds = user?.providerData?.map(
      (entry) => entry.providerId,
    );
    if (
      !selectedProvider ||
      !linkedProviderIds?.includes(selectedProvider.id)
    ) {
      selectedProvider = providerForUser(user);
    }
    if (!selectedProvider) {
      void signOut(auth);
      showSafeError(
        new AccountDeletionError(
          'provider-not-supported',
          'Този акаунт няма поддържан Google, Facebook или Apple вход.',
        ),
      );
      return;
    }
    document.getElementById('account-name').textContent =
      user.displayName || 'Firebase акаунт';
    document.getElementById('account-email').textContent =
      user.email || 'Скрит email от доставчика';
    document.getElementById('account-provider').textContent =
      `Вход с ${providerLabels[selectedProvider.id]}`;
    const avatar = document.getElementById('account-avatar');
    avatar.textContent = (user.displayName || user.email || '?')
      .trim()
      .charAt(0)
      .toUpperCase();
    confirmation.checked = false;
    deleteAction.disabled = true;
    showState('confirm-state');
  }

  onAuthStateChanged(auth, (user) => {
    if (busy) return;
    if (user) showAccount(user);
    else showState('signin-state');
  });

  for (const button of document.querySelectorAll('[data-provider]')) {
    button.addEventListener('click', async () => {
      const providerKey = button.dataset.provider;
      selectedProvider = {
        id: providerKey === 'apple' ? 'apple.com' : `${providerKey}.com`,
        instance: providers[providerKey],
      };
      busy = true;
      showState('progress-state');
      progressMessage.textContent = 'Отваряме защитения вход…';
      try {
        const result = await signInWithPopup(auth, selectedProvider.instance);
        const additionalInfo = getAdditionalUserInfo(result);
        if (additionalInfo?.isNewUser) {
          // Firebase Auth may transiently create a user when a provider identity
          // has never used the app. Remove it immediately instead of presenting
          // a newly created identity as an existing account.
          if (selectedProvider.id === 'apple.com') {
            const credential = OAuthProvider.credentialFromResult(result);
            if (credential?.accessToken) {
              await revokeAccessToken(auth, credential.accessToken);
            }
          }
          await deleteUser(result.user);
          await signOut(auth);
          throw new AccountDeletionError(
            'account-not-found',
            'Не открихме съществуващ акаунт с този профил.',
          );
        }
        showAccount(result.user);
      } catch (error) {
        showSafeError(error);
      } finally {
        busy = false;
      }
    });
  }

  confirmation.addEventListener('change', () => {
    deleteAction.disabled = !confirmation.checked || busy;
  });

  document.getElementById('cancel-action').addEventListener('click', async () => {
    await signOut(auth);
    selectedProvider = null;
    showState('signin-state');
  });

  document.getElementById('signout-action').addEventListener('click', async () => {
    await signOut(auth);
    selectedProvider = null;
    showState('signin-state');
  });

  document.getElementById('retry-action').addEventListener('click', () => {
    const user = auth.currentUser;
    if (user) showAccount(user);
    else showState('signin-state');
  });

  deleteAction.addEventListener('click', async () => {
    const user = auth.currentUser;
    if (!user || !selectedProvider || !confirmation.checked || busy) return;
    busy = true;
    deleteAction.disabled = true;
    showState('progress-state');
    try {
      await deleteAuthenticatedAccount({
        user,
        providerId: selectedProvider.id,
        reauthenticate: async () => {
          const result = await reauthenticateWithPopup(
            user,
            selectedProvider.instance,
          );
          const credential =
            selectedProvider.id === 'apple.com'
              ? OAuthProvider.credentialFromResult(result)
              : null;
          return { user: result.user, accessToken: credential?.accessToken };
        },
        deleteCloudData: (uid) => deleteCloudAccountData(firestore, uid),
        revokeAppleToken: (token) => revokeAccessToken(auth, token),
        deleteAuthUser: deleteUser,
        onProgress: (step) => {
          progressMessage.textContent = progressText(step);
        },
      });
      selectedProvider = null;
      showState('success-state');
    } catch (error) {
      showSafeError(error);
    } finally {
      busy = false;
    }
  });

  async function deleteCloudAccountData(database, uid) {
    const people = collection(database, 'users', uid, 'people');
    while (true) {
      const snapshot = await getDocs(query(people, limit(450)));
      if (snapshot.empty) break;
      const batch = writeBatch(database);
      for (const record of snapshot.docs) batch.delete(record.ref);
      await batch.commit();
    }
    await deleteDoc(doc(database, 'users', uid));
  }

  function showSafeError(error) {
    const code = error?.code || error?.cause?.code || '';
    const safeMessage =
      error instanceof AccountDeletionError
        ? error.message
        : code === 'auth/popup-closed-by-user' ||
            code === 'auth/cancelled-popup-request'
          ? 'Удостоверяването беше отказано. Нищо не е изтрито.'
          : code === 'auth/network-request-failed' || code === 'unavailable'
            ? 'Няма надеждна връзка с услугата. Провери интернета и опитай отново.'
            : code === 'auth/requires-recent-login'
              ? 'Firebase изисква ново удостоверяване. Опитай изтриването отново.'
              : 'Операцията не завърши. Нищо няма да бъде отчетено като изтрито, докато не получим потвърждение.';
    errorMessage.textContent = safeMessage;
    showState('error-state');
  }
}

function progressText(step) {
  return (
    {
      reauthenticating: 'Потвърждаваме отново самоличността ти…',
      'deleting-cloud-data': 'Изтриваме свързаните cloud данни…',
      'revoking-apple-token': 'Прекратяваме достъпа през Apple…',
      'deleting-auth-user': 'Изтриваме Firebase акаунта…',
      complete: 'Изтриването приключи.',
    }[step] || 'Обработваме заявката…'
  );
}
