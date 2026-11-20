/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export default function App() {
  if (typeof window !== 'undefined') {
    window.location.replace('/MEMORY-VAULT/frontend/index.html');
  }
  return null;
}
