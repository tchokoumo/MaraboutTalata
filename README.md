# MaraboutTalata

MaraboutTalata est une application de bureau de supervision système locale, construite avec Tauri 2, Vue 3, TypeScript et Rust. Elle affiche les ressources et processus de la machine en lecture seule. Aucune élévation de privilèges n’est requise.

## Fonctions

- Vue d’ensemble du processeur, des cœurs, de la mémoire vive, du swap et du stockage.
- Liste des processus avec recherche, tri et détails en lecture seule.
- Affichage des volumes montés, avec filtre des montages techniques.
- Actualisation configurable toutes les 3, 5 ou 10 secondes, ou manuelle.
- Préférences d’affichage conservées localement dans le stockage du WebView.

Les commandes de processus affichées sont limitées à 2 048 caractères et certains formats courants de secrets sont masqués. Ce masquage est heuristique et ne garantit pas la détection de toutes les données sensibles.

### Confidentialité des arguments de processus

Pour les processus candidats Codex CLI et Claude Code, les détails renvoyés par `get_process_command` ne contiennent que le nom du processus et l’indicateur de masquage. Les snapshots et les preuves de détection n’incluent pas leurs arguments, et le code de l’application ne les écrit pas dans les journaux. Sous Linux, le détecteur lit au plus les deux premiers arguments, dans une limite totale de 8 194 octets ; un argument incomplet ou tronqué n’est pas utilisé comme preuve, et le tampon temporaire est effacé après lecture.

Limite : `sysinfo::System` conserve les arguments bruts dans ses structures internes en mémoire, car le moniteur collecte aussi les lignes de commande des autres processus. Le cache applicatif ne conserve qu’une commande masquée pour les candidats agents ; leur empreinte de cache n’inclut pas les arguments. Les commandes des autres processus sont masquées par heuristiques et peuvent encore contenir des valeurs sensibles inconnues.

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
