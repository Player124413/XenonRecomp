# Sonic Generations → C++ (XenonRecomp) / Sonic Generations → C++ (XenonRecomp)

This folder contains everything needed to convert the **Xbox 360 executable of Sonic Generations** (`default.xex`) into portable C++ source code using XenonRecomp.

Эта папка содержит всё необходимое, чтобы конвертировать **исполняемый файл Sonic Generations для Xbox 360** (`default.xex`) в переносимый C++-код с помощью XenonRecomp.

> ⚖️ **Legal / Юридическое предупреждение**
> You must provide the game file yourself — dump `default.xex` from your own console or your own copy of the game. The file must be **decrypted** (for example with `xextool`), XenonRecomp does not decrypt retail XEX files. Neither this repository nor its CI workflows distribute any game data.
>
> Файл игры вы должны предоставить сами — сдампить `default.xex` со своей консоли или своей копии игры. Файл должен быть **расшифрован** (например, через `xextool`): XenonRecomp не расшифровывает розничные XEX. Ни этот репозиторий, ни его CI-workflow не распространяют игровые данные.

---

## Quick Start (English)

1. **Get the tools.** Either build the repository (CMake 3.20+, Clang 18+):
   ```bash
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(nproc)
   ```
   …or let `run_unix.sh` build them for you automatically.

2. **Put your decrypted `default.xex` into this folder** (`SonicGenerations/`).

3. **Run the script:**
   ```bash
   ./run_unix.sh          # Linux / macOS
   run_windows.bat        # Windows (after building with Visual Studio / CMake)
   ```

4. **Result:** the generated C++ sources appear in `SonicGenerations/ppc/`.
   The script performs both steps automatically:
   - `XenonAnalyse default.xex switch_tables.toml` — finds jump tables;
   - `XenonRecomp config.toml ../XenonUtils/ppc_context.h` — converts the code.

### Using GitHub Actions instead

The repository ships a **`Sonic Generations` workflow** (`.github/workflows/sonic-generations.yml`). Because the game file cannot be stored in the repository, start the workflow (Actions tab → *Sonic Generations* → *Run workflow*) and **paste a direct link to your decrypted `default.xex`** into the `xex_source` field — that's it. Google Drive links (shared as "Anyone with the link") work too.

| `xex_source` | Meaning |
|---|---|
| `https://…` — a plain link | The workflow downloads `default.xex` from that URL. The link must be a *direct* download (returning the file itself, not a web page). Google Drive links are handled automatically. |
| `release:latest` | Download `default.xex` from the latest release of **your fork** — create a release and attach your decrypted XEX as an asset named `default.xex`. |
| `release:<tag>` | Same, but from a specific release tag. |

After the download the file is validated (it must be a real XEX2/ELF executable), then the workflow builds the tools, detects jump tables, recompiles the game and uploads the generated `ppc/` directory as an artifact (**`sonic-generations-ppc`**). The complete XenonAnalyse/XenonRecomp output is uploaded as the **`sonic-generations-logs`** artifact — even when a step fails — so you can always download and inspect exactly what the tools printed. No game data is ever committed to the repository.

## Быстрый старт (Русский)

1. **Соберите инструменты** (CMake 3.20+, Clang 18+):
   ```bash
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j$(nproc)
   ```
   …или просто запустите `run_unix.sh` — он соберёт их сам.

2. **Положите расшифрованный `default.xex` в эту папку** (`SonicGenerations/`).

3. **Запустите скрипт:**
   ```bash
   ./run_unix.sh          # Linux / macOS
   run_windows.bat        # Windows (после сборки в Visual Studio / CMake)
   ```

4. **Результат:** C++-исходники появятся в `SonicGenerations/ppc/`.
   Скрипт сам выполняет оба шага:
   - `XenonAnalyse default.xex switch_tables.toml` — поиск jump-таблиц;
   - `XenonRecomp config.toml ../XenonUtils/ppc_context.h` — конвертация кода.

### Через GitHub Actions

В репозитории есть workflow **`Sonic Generations`** (`.github/workflows/sonic-generations.yml`). Так как игровой файл нельзя хранить в репозитории, при запуске workflow (вкладка Actions → *Sonic Generations* → *Run workflow*) **просто вставьте прямую ссылку на ваш расшифрованный `default.xex`** в поле `xex_source` — и всё. Ссылки на Google Drive (с доступом «Все, у кого есть ссылка») тоже поддерживаются.

| `xex_source` | Значение |
|---|---|
| `https://…` — обычная ссылка | Workflow скачает `default.xex` по этой ссылке. Ссылка должна быть *прямой* (отдавать сам файл, а не веб-страницу). Google Drive обрабатывается автоматически. |
| `release:latest` | Скачать `default.xex` из последнего релиза **вашего форка** — создайте релиз и прикрепите свой расшифрованный XEX как файл с именем `default.xex`. |
| `release:<tag>` | То же, но из конкретного тега релиза. |

После скачивания файл проверяется (это должен быть настоящий XEX2/ELF), затем workflow соберёт инструменты, найдёт jump-таблицы, перекомпилирует игру и выложит папку `ppc/` как артефакт (**`sonic-generations-ppc`**). Полный вывод XenonAnalyse/XenonRecomp выкладывается отдельным артефактом **`sonic-generations-logs`** — даже если какой-то шаг упал, — так что вы всегда можете скачать и посмотреть, что именно напечатали инструменты. Игровые данные в репозиторий не попадают.

---

## Configuration / Конфигурация

`config.toml` is intentionally minimal:

- **CRT helper addresses are detected automatically.** `__restgprlr_14`, `__savegprlr_14`, `__restfpr_14`, `__savefpr_14`, `__restvmx_14`, `__savevmx_14`, `__restvmx_64`, `__savevmx_64` are found by scanning the code sections; the tool prints every address it detected. You can override any of them explicitly if needed.
- **Title updates:** if you have `default.xexp`, uncomment `patch_file_path` / `patched_file_path` in `config.toml` — XenonRecomp will patch the XEX automatically and recompile the patched image.
- **Optimizations** (`skip_lr`, `non_volatile_as_local`, …) are disabled by default. Enable them only after you have a running recompilation.

`config.toml` намеренно минимален:

- **Адреса CRT-хелперов определяются автоматически.** Функции `__restgprlr_14`, `__savegprlr_14`, `__restfpr_14`, `__savefpr_14`, `__restvmx_14`, `__savevmx_14`, `__restvmx_64`, `__savevmx_64` находятся сканированием секций кода; инструмент печатает каждый найденный адрес. При желании любой адрес можно задать вручную.
- **Титульные обновления:** если у вас есть `default.xexp`, раскомментируйте `patch_file_path` / `patched_file_path` — XenonRecomp сам применит патч и перекомпилирует обновлённый образ.
- **Оптимизации** (`skip_lr`, `non_volatile_as_local`, …) по умолчанию выключены. Включайте их, только когда перекомпиляция уже работает.

## Troubleshooting / Решение проблем

| Symptom / Симптом | Cause & fix / Причина и решение |
|---|---|
| `ERROR: Unable to parse the executable…` | The XEX is still encrypted or corrupt. Decrypt it (`xextool -k …`) and re-dump. / XEX зашифрован или повреждён. Расшифруйте его и сдампите заново. |
| `std::bad_alloc` / crash | Should no longer happen: header, section and compression bounds are validated and reported as clear errors. If you still see it, your dump is truncated — re-dump. / Больше не должно возникать: все границы проверяются и ошибки сообщаются явно. Если всё же видите — дамп обрезан, пере-дампите. |
| `WARNING: Switch table file … was not found` | Run XenonAnalyse first (the scripts do it for you). / Сначала запустите XenonAnalyse (скрипты делают это сами). |
| `ERROR: Switch case … is trying to jump outside function` | A jump table pattern XenonAnalyse could not fully map. Add explicit boundaries via `functions = [{ address = …, size = … }]` (see main README). / Паттерн jump-таблицы не распознан до конца — задайте границы функции вручную в `functions`. |
| Generated code compiles but the game doesn't run | Expected: XenonRecomp only produces C++. You still need a runtime (memory, GPU, audio, hooks), like the one [UnleashedRecomp](https://github.com/hedge-dev/UnleashedRecomp) built for Sonic Unleashed. / Ожидаемо: XenonRecomp только генерирует C++. Для запуска нужен рантайм (память, GPU, звук, хуки), как в [UnleashedRecomp](https://github.com/hedge-dev/UnleashedRecomp). |
