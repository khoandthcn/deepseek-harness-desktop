#!/usr/bin/env node
// Prepare a deepseek-ai/deepseek-harness checkout for the plain (no SOC) desktop build.
//
//   node scripts/patch-upstream-plain.mjs <path-to-upstream-checkout>
//
// Changes 1-2 are for users upgrading from this repository's SOC builds; 3 is
// for everyone who runs the app on a model gateway other than DeepSeek's own:
// 1. A Desktop profile left by a dsh 0.1.x install is moved aside on first
//    start, keeping the user's settings rows for plugins the new runtime ships.
//    Without it the old packages in the profile shadow the bundled runtime and
//    startup fails with "required plugins did not activate".
// 2. A saved Session whose recorded agent preset is no longer registered
//    (`soc-cloud`, `standard-brave`) resumes under the default preset instead
//    of failing with "Unknown agent preset". Upstream already does this for
//    blank Sessions (ui-workspace navigation.ts, restoreBlank).
// 3. No DeepSeek-only welcome window. Desktop otherwise opens a window before
//    the workspace offering only DeepSeek sign-in or an official DeepSeek key
//    until one of them exists. The workspace opens directly instead, and its
//    first-run model step (enabled on Desktop too) leads with creating a custom
//    provider, keeping DeepSeek sign-in or key as the alternative.
// 4. Updates from this repository's GitHub Releases. Upstream drops the update
//    feed from unsigned builds. With DSH_DESKTOP_UPDATE_FEED_URL set at
//    packaging time they keep one (a generic feed, nightly channel): Windows
//    downloads and installs through upstream's own flow (electron-updater skips
//    the signature check when the feed names no publisher). Squirrel.Mac
//    refuses ad-hoc signed updates, so on macOS a found update opens its
//    release page (DSH_DESKTOP_RELEASES_URL) instead of downloading.
import { createHash } from 'node:crypto'
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const root = resolve(process.argv[2] ?? 'upstream')
const here = resolve(import.meta.dirname, '..')

const sha256 = path => createHash('sha256').update(readFileSync(path)).digest('hex')

for (const [source, target] of [
  ['overrides/plain/legacy-profile.ts', 'apps/desktop/src/legacy-profile.ts'],
  ['overrides/plain/legacy-profile.spec.ts', 'apps/desktop/tests/legacy-profile.spec.ts'],
  ['overrides/plain/ProviderOnboarding.module.css', 'packages/client/ui-settings-models/src/client/ProviderOnboarding.module.css'],
]) {
  copyFileSync(join(here, source), join(root, target))
  console.log(`copied: ${target}`)
}

// Replaces an upstream file only while it is the version the override was
// written against, so an upstream change fails here instead of being dropped.
const ONBOARDING_DIALOG = 'packages/client/ui-settings-models/src/client/DeepSeekOnboardingDialog.tsx'
const ONBOARDING_DIALOG_UPSTREAM = '0a1ae2e32c4ca822f72118acd33d4f8770968098598f1e4402e8af65c1fe8454'
{
  const target = join(root, ONBOARDING_DIALOG)
  const source = join(here, 'overrides/plain/DeepSeekOnboardingDialog.tsx')
  if (sha256(target) === sha256(source)) {
    console.log(`already overridden: ${ONBOARDING_DIALOG}`)
  } else if (sha256(target) !== ONBOARDING_DIALOG_UPSTREAM) {
    throw new Error(`patch-upstream-plain: ${ONBOARDING_DIALOG} changed upstream; port overrides/plain/DeepSeekOnboardingDialog.tsx to it`)
  } else {
    copyFileSync(source, target)
    console.log(`overridden: ${ONBOARDING_DIALOG}`)
  }
}

function patch(relativePath, from, to) {
  const path = join(root, relativePath)
  const text = readFileSync(path, 'utf8')
  if (text.includes(to)) {
    console.log(`already patched: ${relativePath}`)
    return
  }
  const count = text.split(from).length - 1
  if (count !== 1) {
    throw new Error(`patch-upstream-plain: expected exactly one match in ${relativePath}, found ${count}:\n${from}`)
  }
  writeFileSync(path, text.replace(from, to))
  console.log(`patched: ${relativePath}`)
}

patch(
  'apps/desktop/src/project-manager.ts',
  "import { readDesktopRuntime } from './runtime-tree.ts'\n",
  "import { readDesktopRuntime } from './runtime-tree.ts'\nimport { retireLegacyPackageProfile } from './legacy-profile.ts'\n",
)
// Before the lock: the lock file lives inside the directory that moves.
patch(
  'apps/desktop/src/project-manager.ts',
  "  async applyRelease(): Promise<void> {\n    await this.withLock(() => {\n",
  "  async applyRelease(): Promise<void> {\n"
  + "    const retired = retireLegacyPackageProfile(this.paths.profile, this.runtime.dsh)\n"
  + "    if (retired !== undefined) {\n"
  + "      const dropped = retired.dropped.length === 0 ? '' : `; settings dropped for ${retired.dropped.join(', ')}`\n"
  + "      process.stderr.write(`desktop project: moved the dsh 0.1.x profile to ${retired.backup}${dropped}\\n`)\n"
  + "    }\n"
  + "    await this.withLock(() => {\n",
)

// Resume under the default preset once the recorded one is gone.
patch(
  'packages/api/session-controller/src/agent.ts',
  "    const composition = await this.composeAgent(this.presetForObservation(observation))\n",
  "    const composition = await this.composeResumed(this.presetForObservation(observation))\n",
)
patch(
  'packages/api/session-controller/src/agent.ts',
  "  private liveAgent(sessionId: SessionId): ApiSessionAgentResult | undefined {\n",
  "  /**\n"
  + "   * Compose a resumed Agent under its recorded preset, or under the default once that preset is no longer\n"
  + "   * registered — an application update can remove a preset that saved Sessions still name.\n"
  + "   * @param recorded - preset the Session log recorded, if any.\n"
  + "   * @returns the composition for the recorded preset, or for the default when the recorded one is unknown.\n"
  + "   */\n"
  + "  private async composeResumed(recorded: string | undefined): Promise<ApiSessionComposition> {\n"
  + "    try {\n"
  + "      return await this.composeAgent(recorded)\n"
  + "    } catch (error: unknown) {\n"
  + "      if (recorded === undefined || remoteErrorOf(error)?.code !== 'agent-preset/not-found') throw error\n"
  + "      return await this.composeAgent(undefined)\n"
  + "    }\n"
  + "  }\n"
  + "\n"
  + "  private liveAgent(sessionId: SessionId): ApiSessionAgentResult | undefined {\n",
)

// 3. The workspace opens without the DeepSeek-only welcome window...
patch(
  'apps/desktop/src/welcome-api.ts',
  "export function needsWelcome(authentication: WelcomeAuthentication): boolean {\n  return !authentication.loggedIn && !authentication.hasApiKey\n}",
  "export function needsWelcome(_authentication: WelcomeAuthentication): boolean {\n  // deepseek-harness-desktop: the workspace's own first-run step offers custom providers too.\n  return false\n}",
)
// ...and the first-run model step runs on Desktop as it does on the Web.
patch(
  'packages/client/ui-settings-models/src/client/index.ts',
  "  const credentialOnboarding = configured.credentialOnboarding && !('dshDesktop' in globalThis)\n",
  "  const credentialOnboarding = configured.credentialOnboarding\n",
)

const ONBOARDING_COPY = {
  en: {
    anchor: "  onboardingSaving: 'Saving…',\n",
    entries: {
      onboardingChooseTitle: 'Set up a model provider',
      onboardingChooseDescription: 'DeepSeek Harness needs a model provider before it can work. Create a custom provider for any OpenAI- or Anthropic-compatible endpoint, such as your organization\u2019s model gateway, or use a DeepSeek account or API key.',
      onboardingCreateCustom: 'Create a custom provider',
      onboardingUseDeepSeek: 'Use a DeepSeek account or API key',
      onboardingBack: 'Back',
      onboardingCustomTitle: 'Create a custom provider',
      onboardingCustomDescription: 'Fill in the form below, following these steps:',
      onboardingGuideRoute: 'Provider ID: a short lowercase name such as my-gateway. It identifies the provider and names its stored key.',
      onboardingGuideEndpoint: 'Base URL and API protocol: the endpoint your provider documents, and whether it speaks OpenAI Chat Completions, OpenAI Responses, or Anthropic Messages.',
      onboardingGuideKey: 'API key: saved in the local credential store, never in the settings file.',
      onboardingGuideModels: 'Models: use Fetch available models, or add model IDs by hand.',
      onboardingGuideCreate: 'Create, then pick one of the new models in the model picker under the message box.',
      onboardingCustomDoneTitle: 'Provider created',
      onboardingCustomDone: 'Your provider is saved. Pick one of its models in the model picker under the message box to start a session.',
      onboardingDone: 'Get started',
    },
  },
  zh: {
    anchor: "  onboardingSaving: '保存中…',\n",
    entries: {
      onboardingChooseTitle: '设置模型提供方',
      onboardingChooseDescription: 'DeepSeek Harness 需要先配置模型提供方。你可以为任意 OpenAI 或 Anthropic 兼容端点（例如所在机构的模型网关）创建自定义提供方，或使用 DeepSeek 账号或 API Key。',
      onboardingCreateCustom: '创建自定义提供方',
      onboardingUseDeepSeek: '使用 DeepSeek 账号或 API Key',
      onboardingBack: '返回',
      onboardingCustomTitle: '创建自定义提供方',
      onboardingCustomDescription: '按以下步骤填写下方表单：',
      onboardingGuideRoute: 'Provider ID：简短的小写名称，例如 my-gateway，用于标识提供方并命名其密钥。',
      onboardingGuideEndpoint: 'API 地址与协议：提供方文档中的端点，以及它使用 OpenAI Chat Completions、OpenAI Responses 还是 Anthropic Messages。',
      onboardingGuideKey: 'API Key：保存在本地凭据存储中，不会写入设置文件。',
      onboardingGuideModels: '模型：点击获取可用模型，或手动添加模型 ID。',
      onboardingGuideCreate: '点击创建，然后在输入框下方的模型选择器中选择一个新模型。',
      onboardingCustomDoneTitle: '提供方已创建',
      onboardingCustomDone: '提供方已保存。在输入框下方的模型选择器中选择它的一个模型即可开始会话。',
      onboardingDone: '开始使用',
    },
  },
  ja: {
    anchor: "  'onboardingSaving': '保存中…',\n",
    entries: {
      onboardingChooseTitle: 'モデルプロバイダーを設定',
      onboardingChooseDescription: 'DeepSeek Harness を使うにはモデルプロバイダーが必要です。OpenAI または Anthropic 互換の任意のエンドポイント（組織のモデルゲートウェイなど）用にカスタムプロバイダーを作成するか、DeepSeek アカウントまたは API キーを使用してください。',
      onboardingCreateCustom: 'カスタムプロバイダーを作成',
      onboardingUseDeepSeek: 'DeepSeek アカウントまたは API キーを使用',
      onboardingBack: '戻る',
      onboardingCustomTitle: 'カスタムプロバイダーを作成',
      onboardingCustomDescription: '次の手順に従って下のフォームに入力してください：',
      onboardingGuideRoute: 'プロバイダーID：my-gateway のような短い小文字の名前。プロバイダーを識別し、保存するキーの名前にもなります。',
      onboardingGuideEndpoint: 'ベースURLと API プロトコル：プロバイダーのドキュメントにあるエンドポイントと、OpenAI Chat Completions、OpenAI Responses、Anthropic Messages のどれを使うか。',
      onboardingGuideKey: 'API キー：設定ファイルではなく、ローカルの資格情報ストアに保存されます。',
      onboardingGuideModels: 'モデル：「利用可能なモデルを取得」を使うか、モデルIDを手動で追加します。',
      onboardingGuideCreate: '作成したら、メッセージ欄の下のモデル選択で新しいモデルを選びます。',
      onboardingCustomDoneTitle: 'プロバイダーを作成しました',
      onboardingCustomDone: 'プロバイダーを保存しました。メッセージ欄の下のモデル選択でそのモデルを選ぶとセッションを開始できます。',
      onboardingDone: '始める',
    },
  },
  es: {
    anchor: "  onboardingSaving: 'Guardando…',\n",
    entries: {
      onboardingChooseTitle: 'Configurar un proveedor de modelos',
      onboardingChooseDescription: 'DeepSeek Harness necesita un proveedor de modelos para funcionar. Cree un proveedor personalizado para cualquier punto final compatible con OpenAI o Anthropic, como la pasarela de modelos de su organización, o use una cuenta o clave de API de DeepSeek.',
      onboardingCreateCustom: 'Crear un proveedor personalizado',
      onboardingUseDeepSeek: 'Usar una cuenta o clave de API de DeepSeek',
      onboardingBack: 'Atrás',
      onboardingCustomTitle: 'Crear un proveedor personalizado',
      onboardingCustomDescription: 'Complete el formulario de abajo siguiendo estos pasos:',
      onboardingGuideRoute: 'ID del proveedor: un nombre corto en minúsculas, como my-gateway. Identifica al proveedor y da nombre a su clave guardada.',
      onboardingGuideEndpoint: 'URL base y protocolo de API: el punto final que documenta su proveedor y si usa OpenAI Chat Completions, OpenAI Responses o Anthropic Messages.',
      onboardingGuideKey: 'Clave de API: se guarda en el almacén local de credenciales, nunca en el archivo de configuración.',
      onboardingGuideModels: 'Modelos: use Buscar modelos disponibles o añada los ID de modelo a mano.',
      onboardingGuideCreate: 'Cree el proveedor y elija uno de los nuevos modelos en el selector de modelos bajo el cuadro de mensaje.',
      onboardingCustomDoneTitle: 'Proveedor creado',
      onboardingCustomDone: 'Su proveedor está guardado. Elija uno de sus modelos en el selector bajo el cuadro de mensaje para iniciar una sesión.',
      onboardingDone: 'Empezar',
    },
  },
  fr: {
    anchor: "  onboardingSaving: 'Sauvegarde…',\n",
    entries: {
      onboardingChooseTitle: 'Configurer un fournisseur de modèles',
      onboardingChooseDescription: 'DeepSeek Harness a besoin d’un fournisseur de modèles pour fonctionner. Créez un fournisseur personnalisé pour tout point de terminaison compatible OpenAI ou Anthropic, comme la passerelle de modèles de votre organisation, ou utilisez un compte ou une clé API DeepSeek.',
      onboardingCreateCustom: 'Créer un fournisseur personnalisé',
      onboardingUseDeepSeek: 'Utiliser un compte ou une clé API DeepSeek',
      onboardingBack: 'Retour',
      onboardingCustomTitle: 'Créer un fournisseur personnalisé',
      onboardingCustomDescription: 'Remplissez le formulaire ci-dessous en suivant ces étapes :',
      onboardingGuideRoute: 'ID du fournisseur : un nom court en minuscules, comme my-gateway. Il identifie le fournisseur et nomme sa clé enregistrée.',
      onboardingGuideEndpoint: 'URL de base et protocole d’API : le point de terminaison documenté par votre fournisseur, et s’il utilise OpenAI Chat Completions, OpenAI Responses ou Anthropic Messages.',
      onboardingGuideKey: 'Clé API : enregistrée dans le magasin local d’identifiants, jamais dans le fichier de paramètres.',
      onboardingGuideModels: 'Modèles : utilisez Récupérer les modèles disponibles, ou ajoutez les ID de modèle à la main.',
      onboardingGuideCreate: 'Créez le fournisseur, puis choisissez l’un des nouveaux modèles dans le sélecteur sous la zone de message.',
      onboardingCustomDoneTitle: 'Fournisseur créé',
      onboardingCustomDone: 'Votre fournisseur est enregistré. Choisissez l’un de ses modèles dans le sélecteur sous la zone de message pour démarrer une session.',
      onboardingDone: 'Commencer',
    },
  },
  de: {
    anchor: "  onboardingSaving: 'Speichern…',\n",
    entries: {
      onboardingChooseTitle: 'Modellanbieter einrichten',
      onboardingChooseDescription: 'DeepSeek Harness braucht einen Modellanbieter, bevor es arbeiten kann. Erstellen Sie einen benutzerdefinierten Anbieter für einen beliebigen OpenAI- oder Anthropic-kompatiblen Endpunkt, etwa das Modell-Gateway Ihrer Organisation, oder verwenden Sie ein DeepSeek-Konto oder einen API-Schlüssel.',
      onboardingCreateCustom: 'Benutzerdefinierten Anbieter erstellen',
      onboardingUseDeepSeek: 'DeepSeek-Konto oder API-Schlüssel verwenden',
      onboardingBack: 'Zurück',
      onboardingCustomTitle: 'Benutzerdefinierten Anbieter erstellen',
      onboardingCustomDescription: 'Füllen Sie das Formular unten in diesen Schritten aus:',
      onboardingGuideRoute: 'Anbieter-ID: ein kurzer Name in Kleinbuchstaben wie my-gateway. Er kennzeichnet den Anbieter und benennt seinen gespeicherten Schlüssel.',
      onboardingGuideEndpoint: 'Basis-URL und API-Protokoll: der Endpunkt aus der Dokumentation Ihres Anbieters, und ob er OpenAI Chat Completions, OpenAI Responses oder Anthropic Messages spricht.',
      onboardingGuideKey: 'API-Schlüssel: wird im lokalen Anmeldedatenspeicher abgelegt, nie in der Einstellungsdatei.',
      onboardingGuideModels: 'Modelle: Verfügbare Modelle abrufen verwenden oder Modell-IDs von Hand hinzufügen.',
      onboardingGuideCreate: 'Erstellen, dann eines der neuen Modelle in der Modellauswahl unter dem Nachrichtenfeld wählen.',
      onboardingCustomDoneTitle: 'Anbieter erstellt',
      onboardingCustomDone: 'Ihr Anbieter ist gespeichert. Wählen Sie eines seiner Modelle in der Modellauswahl unter dem Nachrichtenfeld, um eine Sitzung zu starten.',
      onboardingDone: 'Loslegen',
    },
  },
  ru: {
    anchor: "  onboardingSaving: 'Сохранение…',\n",
    entries: {
      onboardingChooseTitle: 'Настройка поставщика моделей',
      onboardingChooseDescription: 'Для работы DeepSeek Harness нужен поставщик моделей. Создайте пользовательского поставщика для любой конечной точки, совместимой с OpenAI или Anthropic (например, шлюза моделей вашей организации), или используйте аккаунт DeepSeek или API-ключ.',
      onboardingCreateCustom: 'Создать пользовательского поставщика',
      onboardingUseDeepSeek: 'Использовать аккаунт DeepSeek или API-ключ',
      onboardingBack: 'Назад',
      onboardingCustomTitle: 'Создать пользовательского поставщика',
      onboardingCustomDescription: 'Заполните форму ниже по этим шагам:',
      onboardingGuideRoute: 'Идентификатор поставщика: короткое имя строчными буквами, например my-gateway. Оно обозначает поставщика и даёт имя его сохранённому ключу.',
      onboardingGuideEndpoint: 'Базовый URL и протокол API: конечная точка из документации поставщика и то, какой протокол она использует — OpenAI Chat Completions, OpenAI Responses или Anthropic Messages.',
      onboardingGuideKey: 'API-ключ: сохраняется в локальном хранилище учётных данных, а не в файле настроек.',
      onboardingGuideModels: 'Модели: нажмите «Получить доступные модели» или добавьте идентификаторы моделей вручную.',
      onboardingGuideCreate: 'Нажмите «Создать», затем выберите одну из новых моделей в списке моделей под полем сообщения.',
      onboardingCustomDoneTitle: 'Поставщик создан',
      onboardingCustomDone: 'Поставщик сохранён. Выберите одну из его моделей в списке под полем сообщения, чтобы начать сеанс.',
      onboardingDone: 'Начать',
    },
  },
  pt: {
    anchor: "  onboardingSaving: 'Salvando…',\n",
    entries: {
      onboardingChooseTitle: 'Configurar um provedor de modelos',
      onboardingChooseDescription: 'O DeepSeek Harness precisa de um provedor de modelos para funcionar. Crie um provedor personalizado para qualquer endpoint compatível com OpenAI ou Anthropic, como o gateway de modelos da sua organização, ou use uma conta ou chave de API da DeepSeek.',
      onboardingCreateCustom: 'Criar um provedor personalizado',
      onboardingUseDeepSeek: 'Usar uma conta ou chave de API da DeepSeek',
      onboardingBack: 'Voltar',
      onboardingCustomTitle: 'Criar um provedor personalizado',
      onboardingCustomDescription: 'Preencha o formulário abaixo seguindo estes passos:',
      onboardingGuideRoute: 'ID do provedor: um nome curto em minúsculas, como my-gateway. Ele identifica o provedor e nomeia a chave salva.',
      onboardingGuideEndpoint: 'URL base e protocolo de API: o endpoint documentado pelo seu provedor e se ele usa OpenAI Chat Completions, OpenAI Responses ou Anthropic Messages.',
      onboardingGuideKey: 'Chave de API: salva no armazenamento local de credenciais, nunca no arquivo de configurações.',
      onboardingGuideModels: 'Modelos: use Buscar modelos disponíveis ou adicione os IDs de modelo manualmente.',
      onboardingGuideCreate: 'Crie o provedor e escolha um dos novos modelos no seletor de modelos abaixo da caixa de mensagem.',
      onboardingCustomDoneTitle: 'Provedor criado',
      onboardingCustomDone: 'Seu provedor foi salvo. Escolha um dos modelos dele no seletor abaixo da caixa de mensagem para iniciar uma sessão.',
      onboardingDone: 'Começar',
    },
  },
}
for (const { anchor, entries } of Object.values(ONBOARDING_COPY)) {
  const lines = Object.entries(entries).map(([key, value]) => `  ${key}: ${JSON.stringify(value)},\n`)
  patch('packages/client/ui-settings-models/src/client/locales.ts', anchor, anchor + lines.join(''))
}

// The upstream tests describe the welcome window this build no longer opens.
patch(
  'apps/desktop/tests/welcome-window.spec.ts',
  "  it('shows the entry after logout only without a separately configured API key', () => {\n    expect(needsWelcome({ loggedIn: true, hasApiKey: false })).toBe(false)\n    expect(needsWelcome({ loggedIn: false, hasApiKey: false })).toBe(true)\n",
  "  it('never shows the entry: the workspace onboarding offers custom providers too', () => {\n    expect(needsWelcome({ loggedIn: true, hasApiKey: false })).toBe(false)\n    expect(needsWelcome({ loggedIn: false, hasApiKey: false })).toBe(false)\n",
)
patch(
  'apps/desktop/tests/welcome-startup.spec.ts',
  "it.each([false, true])('starts welcome onboarding without carrying update focus into login or skip (Windows update=%s)'",
  "// deepseek-harness-desktop: startup never opens the welcome window (needsWelcome is always false).\nit.skip.each([false, true])('starts welcome onboarding without carrying update focus into login or skip (Windows update=%s)'",
)

// 4. Updates from GitHub Releases: the feed for unsigned builds...
patch(
  'apps/desktop/scripts/electron-builder-config.mjs',
  '  const update = unsigned ? undefined : resolveDesktopAutoUpdateConfig(env, resolvedPlatform, resolvedArch)\n',
  '  // deepseek-harness-desktop: unsigned builds read updates from the feed GitHub Releases serve.\n'
  + '  const update = unsigned\n'
  + "    ? (env.DSH_DESKTOP_UPDATE_FEED_URL ? { publicUrl: env.DSH_DESKTOP_UPDATE_FEED_URL, channel: 'nightly' } : undefined)\n"
  + '    : resolveDesktopAutoUpdateConfig(env, resolvedPlatform, resolvedArch)\n',
)
// ...the release page a macOS build opens...
patch(
  'apps/desktop/scripts/electron-builder-config.mjs',
  "      dshDesktopUpdateChannel: update?.channel ?? 'nightly',\n",
  "      dshDesktopUpdateChannel: update?.channel ?? 'nightly',\n"
  + "      ...(unsigned && packagesMacOS && env.DSH_DESKTOP_RELEASES_URL ? { dshDesktopReleasesUrl: env.DSH_DESKTOP_RELEASES_URL } : {}),\n",
)
// ...and opening it where Squirrel.Mac would refuse the download.
patch(
  'apps/desktop/src/main.ts',
  '  const downloadUpdate = async (version: string, revision = updates.revision): Promise<DesktopUpdateState> => {\n',
  '  // deepseek-harness-desktop: Squirrel.Mac refuses ad-hoc signed updates; the user installs the release by hand.\n'
  + "  const releasesUrl = typeof manifest === 'object' && manifest !== null && 'dshDesktopReleasesUrl' in manifest\n"
  + "    && typeof manifest.dshDesktopReleasesUrl === 'string' && manifest.dshDesktopReleasesUrl.startsWith('https://')\n"
  + '    ? manifest.dshDesktopReleasesUrl : undefined\n'
  + '  const downloadUpdate = async (version: string, revision = updates.revision): Promise<DesktopUpdateState> => {\n'
  + "    if (process.platform === 'darwin' && releasesUrl !== undefined) {\n"
  + '      await shell.openExternal(`${releasesUrl}/tag/v${encodeURIComponent(version)}`)\n'
  + '      return updates.state\n'
  + '    }\n',
)
