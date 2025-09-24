# SwiftTalk (Render Patched)
- Ecrit les données dans `/tmp/swifttalk-data.json` (writable sur Render)
- Ajoute /healthz, bind en 0.0.0.0, Node >= 18, gestion d'erreurs

## Render
- Web Service
- Build: npm install
- Start: npm start
- Env (optionnel):
  - JWT_SECRET=ta-cle
  - DATA_DIR=/tmp  (par défaut déjà /tmp)

Logs utiles:
- "Data file:" -> te montre où la DB JSON est écrite
- "uncaughtException" / "unhandledRejection" si un crash survient
