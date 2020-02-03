## Istruzioni per la generazione del file eseguibile del serverino locale di Firma Figitale One Pin:

- Per creare digiSign_server.exe:

```
    pyinstaller --onefile --windowed --icon=app.ico --clean digiSign_server.py
```

## Risultato:

Il progetto python viene compilato e con esso viene generato un eseguibile nella cartella `dist/` .
