import { createHmac, timingSafeEqual } from "node:crypto";
import { Router, type IRouter, type Request } from "express";
import { logger } from "../lib/logger";

const router: IRouter = Router();
const TELEGRAM_API_BASE = "https://api.telegram.org/bot";
const AUTH_DATA_MAX_AGE_SECONDS = 86_400;

type TelegramUser = {
  id: number;
  first_name: string;
  last_name?: string;
  username?: string;
  language_code?: string;
};

type TelegramUpdate = {
  message?: {
    chat: { id: number };
    text?: string;
    from?: TelegramUser;
  };
  callback_query?: {
    id: string;
    data?: string;
    message?: { chat: { id: number } };
  };
};

type TelegramAuthPayload = {
  initData?: unknown;
};

function getBotToken() {
  const value = process.env["TELEGRAM_BOT_TOKEN"]?.trim();
  return value || undefined;
}

function getWebAppUrl() {
  const value = process.env["TELEGRAM_WEB_APP_URL"]?.trim();
  if (!value) return undefined;
  return value.startsWith("http://") || value.startsWith("https://")
    ? value
    : `https://${value}`;
}

function getWebhookUrl() {
  const baseUrl = (process.env["TELEGRAM_WEBHOOK_URL"] ?? process.env["RENDER_EXTERNAL_URL"])?.trim();
  if (!baseUrl) return undefined;
  const normalizedBaseUrl = baseUrl.startsWith("http://") || baseUrl.startsWith("https://")
    ? baseUrl
    : `https://${baseUrl}`;
  return new URL("/api/telegram/webhook", normalizedBaseUrl).toString();
}

async function telegramRequest<T>(method: string, body: Record<string, unknown>): Promise<T> {
  const token = getBotToken();
  if (!token) throw new Error("TELEGRAM_BOT_TOKEN is not configured");

  const response = await fetch(`${TELEGRAM_API_BASE}${token}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const result = (await response.json()) as { ok: boolean; result?: T; description?: string };
  if (!response.ok || !result.ok) {
    throw new Error(`Telegram ${method} failed: ${result.description ?? response.statusText}`);
  }
  return result.result as T;
}

function isTelegramWebhookRequest(req: Request) {
  const expectedSecret = process.env["TELEGRAM_WEBHOOK_SECRET"];
  return Boolean(expectedSecret) && req.header("x-telegram-bot-api-secret-token") === expectedSecret;
}

function isValidTelegramInitData(initData: string, botToken: string) {
  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  const authDate = Number(params.get("auth_date"));
  if (!receivedHash || !Number.isSafeInteger(authDate)) return false;
  if (Math.abs(Date.now() / 1000 - authDate) > AUTH_DATA_MAX_AGE_SECONDS) return false;

  params.delete("hash");
  const dataCheckString = [...params.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
  const secretKey = createHmac("sha256", "WebAppData").update(botToken).digest();
  const calculatedHash = createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
  const receivedHashBuffer = Buffer.from(receivedHash, "hex");
  const calculatedHashBuffer = Buffer.from(calculatedHash, "hex");
  return receivedHashBuffer.length === calculatedHashBuffer.length && timingSafeEqual(receivedHashBuffer, calculatedHashBuffer);
}

function parseTelegramUser(initData: string) {
  const userValue = new URLSearchParams(initData).get("user");
  if (!userValue) return undefined;
  try {
    return JSON.parse(userValue) as TelegramUser;
  } catch {
    return undefined;
  }
}

async function handleTelegramUpdate(update: TelegramUpdate) {
  const message = update.message;
  if (message?.text?.startsWith("/start")) {
    const webAppUrl = getWebAppUrl();
    if (!webAppUrl) return;
    await telegramRequest("sendMessage", {
      chat_id: message.chat.id,
      text: `ሰላም${message.from?.first_name ? ` ${message.from.first_name}` : ""}! ፈጣን ቢንጎን ለመጫወት ከታች ያለውን ቁልፍ ይጫኑ።`,
      reply_markup: {
        inline_keyboard: [[{ text: "Flash Bingo ክፈት", web_app: { url: webAppUrl } }]],
      },
    });
  }

  const callbackQuery = update.callback_query;
  if (callbackQuery) {
    await telegramRequest("answerCallbackQuery", { callback_query_id: callbackQuery.id });
  }
}

router.post("/telegram/webhook", async (req, res) => {
  if (!isTelegramWebhookRequest(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    await handleTelegramUpdate(req.body as TelegramUpdate);
    res.sendStatus(200);
  } catch (error) {
    req.log?.error({ err: error }, "Telegram update handling failed");
    res.sendStatus(200);
  }
});

router.post("/telegram/auth", (req, res) => {
  const botToken = getBotToken();
  const { initData } = req.body as TelegramAuthPayload;
  if (!botToken || typeof initData !== "string" || !isValidTelegramInitData(initData, botToken)) {
    res.status(401).json({ error: "Invalid Telegram authentication data" });
    return;
  }

  const user = parseTelegramUser(initData);
  if (!user) {
    res.status(401).json({ error: "Telegram user data is missing" });
    return;
  }
  res.json({ user });
});

export async function registerTelegramWebhook() {
  const token = getBotToken();
  const webhookUrl = getWebhookUrl();
  const webAppUrl = getWebAppUrl();
  if (!token || !webhookUrl || !webAppUrl) {
    logger.warn(
      {
        hasBotToken: Boolean(token),
        hasWebhookUrl: Boolean(webhookUrl),
        hasWebAppUrl: Boolean(webAppUrl),
      },
      "Telegram webhook registration skipped because configuration is incomplete",
    );
    return;
  }

  const secretToken = process.env["TELEGRAM_WEBHOOK_SECRET"]?.trim();
  await telegramRequest("setWebhook", {
    url: webhookUrl,
    ...(secretToken ? { secret_token: secretToken } : {}),
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: false,
  });

  const optionalSetup = [
    {
      method: "setChatMenuButton",
      body: {
        menu_button: { type: "web_app", text: "Flash Bingo", web_app: { url: webAppUrl } },
      },
    },
    {
      method: "setMyCommands",
      body: { commands: [{ command: "start", description: "Flash Bingo ክፈት" }] },
    },
  ] as const;

  for (const setup of optionalSetup) {
    try {
      await telegramRequest(setup.method, setup.body);
    } catch (error) {
      logger.warn({ err: error, method: setup.method }, "Optional Telegram bot setup failed");
    }
  }

  logger.info("Telegram webhook registered");
}

export default router;
