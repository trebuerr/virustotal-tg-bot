# TelegramBot with VirusTotal

Check your files in tg

## inf

1. copy file:
```bash
cp .env.example .env 
```
2. put your token in .env: `BOT_TOKEN=your token`

3. run:
```bash
docker build -t virus_scanner
docker run -dit --name virus_scanner virus_scanner
```
**Warning!** you must have download *Docker*