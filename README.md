# MEP,SFA 営業支援ツール

R CREW 向けのインセンティブシミュレーション・資料ダウンロード・披露宴（ナレッジ共有）ツール。
GitHub Pages で公開しています。

## PINロックのしくみ

- 公開している `index.html` には、ツール本体が **PINで暗号化された状態**（AES-256-GCM / PBKDF2-SHA256 60万回）で入っています。
- 正しいPINを入力したときだけブラウザ内で復号されて表示されます。リポジトリを見ても中身は読めません。
- 「この端末で記憶する」にチェックすると、次回からPIN入力を省略できます。ページ下部の「🔒 ロックする」で解除できます。

## ファイル構成

| ファイル | 内容 |
|---|---|
| `index.html` | 公開ページ（ロック画面＋暗号化済みの中身）。**ビルドで生成** |
| `lock-template.html` | ロック画面のテンプレート |
| `build.mjs` | 暗号化／復号スクリプト（Node.js 18以上） |
| `src/app.html` | ツール本体の平文。**Gitには含めない**（`.gitignore`） |

## 中身を編集する手順

```bash
PIN=xxxxxxxx node build.mjs decrypt   # index.html → src/app.html を取り出す
# src/app.html を編集
PIN=xxxxxxxx node build.mjs encrypt   # src/app.html → index.html を作り直す
git add index.html && git commit -m "更新内容" && git push
```

PINを変えるときは、`decrypt` を旧PINで、`encrypt` を新PINで実行します。

## 移行元

Macaly（https://ttq1xeivf182ksekw7sa1kr9.macaly.app）から 2026-10-17 に移行。
