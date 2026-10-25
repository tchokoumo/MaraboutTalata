# MaraboutTalata

MaraboutTalata est une application de bureau de supervision système locale, construite avec Tauri 2, Vue 3, TypeScript et Rust. Elle affiche les ressources et processus de la machine en lecture seule. Aucune élévation de privilèges n’est requise.

## Fonctions

- Vue d’ensemble du processeur, des cœurs, de la mémoire vive, du swap et du stockage.
- Liste des processus avec recherche, tri et détails en lecture seule.
- Affichage des volumes montés, avec filtre des montages techniques.
- Actualisation configurable toutes les 3, 5 ou 10 secondes, ou manuelle.
- Préférences d’affichage conservées localement dans le stockage du WebView.

Les commandes de processus affichées sont limitées à 2 048 caractères et certains formats courants de secrets sont masqués. Ce masquage est heuristique et ne garantit pas la détection de toutes les données sensibles.

## Développement

Prérequis : Node.js et npm, Rust avec Cargo, ainsi que les dépendances système nécessaires à Tauri 2 sur la plateforme cible.

```sh
npm install
npm run tauri dev
```

Pour construire et vérifier les composants séparément :

```sh
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri build
```

Le tableau de bord collecte les ressources natives uniquement dans l’application Tauri. `npm run dev` ou `npm run preview` sert l’interface web sans les commandes natives de supervision.

## Limites de performance

- Chaque échantillon actualise les mesures CPU et mémoire et parcourt la liste des processus. La charge dépend du nombre de processus et des capacités de la machine, en particulier aux intervalles les plus courts.
- Les informations de stockage sont mises en cache et rafraîchies toutes les 30 secondes, indépendamment de l’intervalle choisi pour les autres mesures.
- Les appels au moniteur sont sérialisés par un verrou partagé. Une collecte longue retarde les appels suivants.
- La disponibilité des métriques dépend du système d’exploitation et des droits de lecture de l’utilisateur courant. Sous Linux, `statvfs` distingue l’espace libre de l’espace disponible pour l’utilisateur ; sur les autres plateformes, l’estimation repose sur les données fournies par `sysinfo`.
