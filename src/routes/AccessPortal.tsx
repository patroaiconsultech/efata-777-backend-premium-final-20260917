import React, { FormEvent, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ApiError,
  adminOtpStart,
  adminOtpVerify,
  nativeClaimAccount,
  nativeForgotPassword,
  nativeLogin,
  nativeMfaEnrollConfirm,
  nativeMfaEnrollStart,
  nativeMfaVerify,
  nativeRegister,
  nativeRecoverAccount,
  nativeResetPassword,
  nativeVerifyEmail,
  validateAccessCode,
} from "../api";
import "../access.css";

export const ONBOARDING_DRAFT_KEY = "patroai_hyper_cocreator_onboarding";

type Mode =
  | "login"
  | "admin-otp"
  | "register"
  | "forgot"
  | "reset"
  | "activate"
  | "verify"
  | "claim"
  | "mfa-enroll"
  | "mfa-verify"
  | "recovery-codes";
type RegisterStep = "code" | "cocreator" | "objective" | "credentials";

const GOALS = [
  "Criar uma nova oferta",
  "Repensar meu modelo de negócio",
  "Resolver um desafio operacional",
  "Explorar uma ideia ainda crua",
];

function storeDraft(input: {
  grant: string;
  co_creator_name: string;
  onboarding_goal: string;
}) {
  sessionStorage.setItem(ONBOARDING_DRAFT_KEY, JSON.stringify(input));
}

function friendlyAuthError(error: unknown): string {
  const code = error instanceof ApiError ? error.code : "NETWORK_ERROR";
  const messages: Record<string, string> = {
    INVALID_CREDENTIALS:
      "Não foi possível autenticar com esses dados.",
    AUTH_RATE_LIMITED:
      "Muitas tentativas foram detectadas. Aguarde um pouco antes de tentar novamente.",
    TENANT_SELECTION_REQUIRED:
      "Esta conta pertence a mais de um espaço. Informe o Tenant ID correto.",
    NATIVE_AUTH_DISABLED:
      "O acesso próprio da PatroAI ainda não está ativo nesta implantação.",
    NATIVE_BOOTSTRAP_FORBIDDEN:
      "A configuração inicial não pôde ser concluída.",
    NATIVE_BOOTSTRAP_ALREADY_COMPLETED:
      "A primeira conta segura da PatroAI já foi configurada.",
    PASSWORD_TOO_SHORT:
      "Use uma senha com pelo menos 15 caracteres.",
    PASSWORD_BLOCKLISTED:
      "Escolha uma senha menos previsível.",
    AUTH_CHALLENGE_INVALID:
      "Este link ou desafio expirou ou já foi utilizado.",
    ADMIN_OTP_INVALID:
      "O código administrativo é inválido, expirou ou já foi utilizado.",
    ACCOUNT_RECOVERY_NOT_ALLOWED:
      "Este acesso não pode ser ativado neste momento. Entre em contato com o administrador do seu espaço.",
    ACCOUNT_RECOVERY_ALREADY_COMPLETED:
      "Esta conta já possui uma credencial ativa. Use o login ou a recuperação de senha.",
    MFA_CODE_INVALID:
      "O código de autenticação não foi aceito.",
    MFA_EXACTLY_ONE_FACTOR_REQUIRED:
      "Informe o código do autenticador ou um código de recuperação.",
    NETWORK_ERROR:
      "Não foi possível alcançar a plataforma agora. Verifique a conexão e tente novamente.",
  };
  return messages[code] || `Não foi possível concluir a operação (${code}).`;
}

function friendlyAccessCodeError(error: unknown): string {
  const code = error instanceof ApiError ? error.code : "NETWORK_ERROR";
  const messages: Record<string, string> = {
    ACCESS_CODE_INVALID: "Código não reconhecido.",
    ACCESS_GATE_DISABLED:
      "O cadastro por código ainda não está habilitado nesta implantação.",
    ACCESS_GATE_NOT_CONFIGURED:
      "O acesso por código está habilitado, mas os códigos ainda não foram configurados.",
    NETWORK_ERROR:
      "Não foi possível alcançar o backend para validar o código.",
  };
  return messages[code] || `Não foi possível validar o código (${code}).`;
}

function safeReturnPath(value: string | null): string {
  if (!value) return "/app";
  const clean = value.trim();
  if (clean.startsWith("//") || clean.includes("\\") || clean.includes("://")) return "/app";
  if (/^\/invite\/[A-Za-z0-9_-]{32,}$/.test(clean)) return clean;
  if (/^\/app(?:\?.*)?$/.test(clean)) return clean;
  return "/app";
}

export default function AccessPortal() {
  const navigate = useNavigate();
  const [returnPath] = useState(() =>
    safeReturnPath(new URLSearchParams(window.location.search).get("next")),
  );
  const [mode, setMode] = useState<Mode>("login");
  const [step, setStep] = useState<RegisterStep>("code");
  const [grant, setGrant] = useState("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [goal, setGoal] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [resetToken, setResetToken] = useState("");
  const [issuedResetToken, setIssuedResetToken] = useState("");
  const [tenantId, setTenantId] = useState("patroai");
  const [displayName, setDisplayName] = useState("");
  const [challengeToken, setChallengeToken] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaUri, setMfaUri] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [adminOtpCode, setAdminOtpCode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [actionToken, setActionToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedMode = params.get("mode");
    const token = params.get("token") || "";
    if (requestedMode === "reset") {
      setMode("reset");
      setResetToken(token);
    } else if (requestedMode === "activate" && token) {
      setMode("activate");
      setActionToken(token);
    } else if (requestedMode === "verify" && token) {
      setMode("verify");
      setActionToken(token);
    } else if (requestedMode === "claim" && token) {
      setMode("claim");
      setActionToken(token);
    }
  }, []);

  function switchMode(next: Mode) {
    setMode(next);
    setError("");
    if (next === "register") setStep("code");
  }

  async function beginMfaEnrollment(token: string) {
    const enrollment = await nativeMfaEnrollStart(token);
    setChallengeToken(token);
    setMfaSecret(enrollment.secret);
    setMfaUri(enrollment.otpauth_uri);
    setMfaCode("");
    setMode("mfa-enroll");
  }

  async function submitLogin(event: FormEvent) {
    event.preventDefault();
    if (!email.trim() || !password || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await nativeLogin({
        email: email.trim(),
        password,
        tenant_id: tenantId.trim() || null,
        return_path: returnPath !== "/app" ? returnPath : null,
      });
      if (result.authenticated) {
        navigate(returnPath, { replace: true });
        return;
      }
      if (result.status === "MFA_ENROLLMENT_REQUIRED" && result.challenge_token) {
        await beginMfaEnrollment(result.challenge_token);
        return;
      }
      if (result.status === "MFA_REQUIRED" && result.challenge_token) {
        setChallengeToken(result.challenge_token);
        setMfaCode("");
        setMode("mfa-verify");
        return;
      }
      if (result.status === "EMAIL_VERIFICATION_REQUIRED") {
        setError("Verifique seu e-mail antes de concluir o login.");
        return;
      }
      setError("O acesso requer uma etapa adicional de segurança.");
    } catch (err) {
      // Admin identities provisioned before NativeCredential existed use the
      // governed email-OTP corridor. Only fall back after terminal native
      // credential failures; non-admin identities keep the original response.
      if (err instanceof ApiError && (err.status === 401 || err.status === 423)) {
        try {
          const issue = await adminOtpStart({
            email: email.trim(),
            password,
          });
          setChallengeToken(issue.challenge_token);
          setAdminOtpCode("");
          setPassword("");
          setMode("admin-otp");
          setError("");
          return;
        } catch {
          // Preserve the original login error so the fallback does not expose
          // whether the submitted identity belongs to an administrative user.
        }
      }
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitAdminOtp(event: FormEvent) {
    event.preventDefault();
    if (!challengeToken || !/^\d{6}$/.test(adminOtpCode) || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await adminOtpVerify({
        challenge_token: challengeToken,
        code: adminOtpCode,
      });
      const hasAdminRole = result.roles.some((role) =>
        ["admin", "owner", "orkio_admin", "platform_owner"].includes(role),
      );
      if (!result.authenticated || !hasAdminRole) {
        throw new Error("ADMIN_SESSION_NOT_CREATED");
      }
      setChallengeToken("");
      setAdminOtpCode("");
      navigate(returnPath, { replace: true });
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  function passwordsMatch(): boolean {
    if (password !== confirmPassword) {
      setError("As senhas não conferem.");
      return false;
    }
    if (password.length < 15) {
      setError("Use uma senha com pelo menos 15 caracteres.");
      return false;
    }
    return true;
  }

  async function submitCode(event: FormEvent) {
    event.preventDefault();
    if (!code.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await validateAccessCode(code.trim());
      setGrant(response.grant);
      setStep("cocreator");
    } catch (err) {
      setError(friendlyAccessCodeError(err));
    } finally {
      setBusy(false);
    }
  }

  function submitName(event: FormEvent) {
    event.preventDefault();
    const clean = name.trim();
    if (clean.length < 2) return;
    setName(clean);
    setStep("objective");
  }

  function continueToIdentity() {
    if (!grant || !name || !goal) return;
    storeDraft({ grant, co_creator_name: name, onboarding_goal: goal });
    setStep("credentials");
    setError("");
  }

  async function submitRegister(event: FormEvent) {
    event.preventDefault();
    if (!grant || !name || !goal || !email.trim() || !password || busy) return;
    if (!passwordsMatch()) return;
    setBusy(true);
    setError("");
    try {
      const result = await nativeRegister({
        grant,
        email: email.trim(),
        display_name: displayName.trim() || email.trim(),
        password,
        co_creator_name: name,
        onboarding_goal: goal,
      });
      sessionStorage.removeItem(ONBOARDING_DRAFT_KEY);
      if (result.authenticated) {
        navigate(returnPath, { replace: true });
        return;
      }
      const token = result.verification_token || result.claim_token || "";
      setActionToken(token);
      if (result.status === "ACCOUNT_RECOVERY_REQUIRED" && token) {
        setMode("activate");
      } else if (result.status === "ACCOUNT_CLAIM_VERIFICATION_REQUIRED" && token) {
        setMode("claim");
      } else if (token) {
        setMode("verify");
      } else {
        setMode("login");
      }
      setError(
        result.status === "ACCOUNT_RECOVERY_REQUIRED"
          ? "Se a conta for elegível, enviaremos a etapa segura de ativação para o e-mail informado."
          : result.authenticated
            ? "Conta criada. Entrando na plataforma..."
            : "Se o cadastro for elegível, enviaremos a próxima etapa para o e-mail informado.",
      );
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitEmailAction(event: FormEvent) {
    event.preventDefault();
    if (!actionToken || busy) return;
    setBusy(true);
    setError("");
    try {
      if (mode === "claim") await nativeClaimAccount(actionToken);
      else await nativeVerifyEmail(actionToken);
      setMode("login");
      setActionToken("");
      setError("E-mail confirmado. Entre com sua credencial.");
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitMfaEnrollment(event: FormEvent) {
    event.preventDefault();
    if (!challengeToken || !mfaCode.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await nativeMfaEnrollConfirm({
        challenge_token: challengeToken,
        code: mfaCode.trim(),
      });
      setRecoveryCodes(result.recovery_codes || []);
      setMode("recovery-codes");
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitMfaVerify(event: FormEvent) {
    event.preventDefault();
    if (!challengeToken || !mfaCode.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await nativeMfaVerify({
        challenge_token: challengeToken,
        code: useRecoveryCode ? null : mfaCode.trim(),
        recovery_code: useRecoveryCode ? mfaCode.trim() : null,
      });
      if (!result.authenticated) throw new Error("MFA_SESSION_NOT_CREATED");
      navigate(returnPath, { replace: true });
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitForgot(event: FormEvent) {
    event.preventDefault();
    if (!email.trim() || busy) return;
    setBusy(true);
    setError("");
    setIssuedResetToken("");
    try {
      const response = await nativeForgotPassword({
        email: email.trim(),
        return_path: returnPath !== "/app" ? returnPath : null,
      });
      if (response.reset_token) {
        setIssuedResetToken(response.reset_token);
        setResetToken(response.reset_token);
      }
      setError("Se houver uma conta elegível para este e-mail, enviaremos as instruções.");
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitAccountRecovery(event: FormEvent) {
    event.preventDefault();
    if (!actionToken.trim() || !password || busy) return;
    if (!passwordsMatch()) return;
    setBusy(true);
    setError("");
    try {
      await nativeRecoverAccount({
        token: actionToken.trim(),
        password,
        password_confirm: confirmPassword,
      });
      setMode("login");
      setActionToken("");
      setPassword("");
      setConfirmPassword("");
      setError("Acesso ativado com segurança. Entre com sua nova credencial.");
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitReset(event: FormEvent) {
    event.preventDefault();
    if (!resetToken.trim() || !password || busy) return;
    if (!passwordsMatch()) return;
    setBusy(true);
    setError("");
    try {
      await nativeResetPassword({
        token: resetToken.trim(),
        password,
        password_confirm: confirmPassword,
      });
      setMode("login");
      setPassword("");
      setConfirmPassword("");
      setError("Senha redefinida. Todas as sessões anteriores foram revogadas.");
    } catch (err) {
      setError(friendlyAuthError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="access-portal" id="main-content">
      <div className="access-portal__glow" aria-hidden="true" />
      <section className="access-card" aria-labelledby="access-title">
        <Link className="access-card__back" to="/">Voltar à experiência</Link>
        <p className="access-eyebrow">PATROAI · ACESSO PROTEGIDO</p>
        <h1 id="access-title">Entre no núcleo PatroAI.</h1>
        <p className="access-lead">
          Identidade protegida e controles adicionais para contas privilegiadas.
        </p>

        {!["verify", "claim", "activate", "admin-otp", "mfa-enroll", "mfa-verify", "recovery-codes"].includes(mode) ? (
          <div className="access-tabs" role="tablist" aria-label="Modo de acesso">
            <button type="button" className={mode === "login" ? "active" : ""} onClick={() => switchMode("login")}>Entrar</button>
            <button type="button" className={mode === "register" ? "active" : ""} onClick={() => switchMode("register")}>Código</button>
          </div>
        ) : null}

        {mode === "login" ? (
          <form className="access-step" onSubmit={submitLogin}>
            <span>SESSÃO PATROAI</span>
            <h2>Bem-vindo de volta.</h2>
            <p>Use sua credencial PatroAI. Contas administrativas exigem segundo fator.</p>
            <label><span>E-mail</span><input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" inputMode="email" placeholder="voce@empresa.com" /></label>
            <label><span>Senha</span><input value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" type={showPassword ? "text" : "password"} placeholder="Sua senha" /></label>
            <label><span>Tenant ID <small>(somente se sua conta usa mais de um espaço)</small></span><input value={tenantId} onChange={(e) => setTenantId(e.target.value)} autoComplete="off" /></label>
            <button className="access-text-button" type="button" onClick={() => setShowPassword((v) => !v)}>{showPassword ? "Ocultar senha" : "Mostrar senha"}</button>
            <button className="access-primary" disabled={busy}>{busy ? "Abrindo sessão..." : "Entrar com segurança"}</button>
            <button className="access-text-button" type="button" onClick={() => switchMode("forgot")}>Esqueci minha senha</button>
          </form>
        ) : null}

        {mode === "admin-otp" ? (
          <form className="access-step" onSubmit={submitAdminOtp}>
            <span>ACESSO ADMINISTRATIVO</span>
            <h2>Confirme o código enviado ao seu e-mail.</h2>
            <p>O código tem seis dígitos, expira em poucos minutos e pode ser usado uma única vez.</p>
            <label>
              <span>Código administrativo</span>
              <input
                value={adminOtpCode}
                onChange={(event) => setAdminOtpCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
              />
            </label>
            <button className="access-primary" disabled={busy || adminOtpCode.length !== 6}>
              {busy ? "Validando..." : "Concluir acesso"}
            </button>
            <button
              className="access-text-button"
              type="button"
              disabled={busy}
              onClick={() => {
                setMode("login");
                setChallengeToken("");
                setAdminOtpCode("");
                setError("");
              }}
            >
              Voltar ao login
            </button>
          </form>
        ) : null}

        {mode === "verify" || mode === "claim" ? (
          <form className="access-step" onSubmit={submitEmailAction}>
            <span>{mode === "claim" ? "VÍNCULO DE CONTA" : "CONFIRMAÇÃO DE E-MAIL"}</span>
            <h2>{mode === "claim" ? "Confirme que esta conta é sua." : "Confirme seu endereço de e-mail."}</h2>
            <p>Por segurança, o link não é consumido automaticamente. Confirme abaixo para concluir esta etapa.</p>
            {!actionToken ? <label><span>Token</span><input value={actionToken} onChange={(e) => setActionToken(e.target.value)} autoComplete="off" /></label> : null}
            <button className="access-primary" disabled={busy || !actionToken}>{busy ? "Confirmando..." : "Confirmar"}</button>
          </form>
        ) : null}

        {mode === "mfa-enroll" ? (
          <form className="access-step" onSubmit={submitMfaEnrollment}>
            <span>SEGUNDO FATOR OBRIGATÓRIO</span>
            <h2>Proteja sua conta administrativa.</h2>
            <p>Adicione a chave abaixo ao seu aplicativo autenticador e informe o código de 6 dígitos.</p>
            <div className="access-security-secret"><strong>Chave TOTP</strong><code>{mfaSecret}</code></div>
            <details><summary>URI técnica</summary><code className="access-break">{mfaUri}</code></details>
            <label><span>Código do autenticador</span><input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={8} /></label>
            <button className="access-primary" disabled={busy}>{busy ? "Validando..." : "Ativar segundo fator"}</button>
          </form>
        ) : null}

        {mode === "mfa-verify" ? (
          <form className="access-step" onSubmit={submitMfaVerify}>
            <span>SEGUNDO FATOR</span>
            <h2>Confirme sua identidade.</h2>
            <label><span>{useRecoveryCode ? "Código de recuperação" : "Código do autenticador"}</span><input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} autoComplete="one-time-code" /></label>
            <button className="access-text-button" type="button" onClick={() => { setUseRecoveryCode((v) => !v); setMfaCode(""); }}>{useRecoveryCode ? "Usar autenticador" : "Usar código de recuperação"}</button>
            <button className="access-primary" disabled={busy}>{busy ? "Validando..." : "Concluir login"}</button>
          </form>
        ) : null}

        {mode === "recovery-codes" ? (
          <div className="access-step">
            <span>RECUPERAÇÃO MFA</span>
            <h2>Guarde estes códigos em local seguro.</h2>
            <p>Eles aparecem uma única vez. Cada código pode ser usado apenas uma vez.</p>
            <div className="access-recovery-codes">{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div>
            <button className="access-primary" type="button" onClick={() => navigate(returnPath, { replace: true })}>Já guardei os códigos</button>
          </div>
        ) : null}

        {mode === "forgot" ? (
          <form className="access-step" onSubmit={submitForgot}>
            <span>RECUPERAÇÃO</span><h2>Vamos recuperar seu acesso.</h2>
            <p>Informe o e-mail. A resposta permanece uniforme, exista ou não uma conta elegível.</p>
            <label><span>E-mail</span><input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" inputMode="email" /></label>
            <button className="access-primary" disabled={busy}>{busy ? "Preparando..." : "Solicitar redefinição"}</button>
            {issuedResetToken ? <p className="access-note">Token disponível somente em ambiente de teste: {issuedResetToken}</p> : null}
            <button className="access-text-button" type="button" onClick={() => switchMode("reset")}>Já tenho um token</button>
          </form>
        ) : null}

        {mode === "activate" ? (
          <form className="access-step" onSubmit={submitAccountRecovery}>
            <span>ATIVAÇÃO SEGURA</span><h2>Defina sua primeira senha PatroAI.</h2>
            <p>Este link prova a posse do seu e-mail. Nenhum tenant ou permissão será criado ou reativado por esta etapa.</p>
            {!actionToken ? <label><span>Token</span><input value={actionToken} onChange={(e) => setActionToken(e.target.value)} autoComplete="off" /></label> : null}
            <label><span>Nova senha</span><input value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" type={showPassword ? "text" : "password"} placeholder="Mínimo de 15 caracteres" /></label>
            <label><span>Repetir nova senha</span><input value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} autoComplete="new-password" type={showConfirmPassword ? "text" : "password"} /></label>
            <div className="access-inline-actions">
              <button className="access-text-button" type="button" onClick={() => setShowPassword((v) => !v)}>{showPassword ? "Ocultar senha" : "Mostrar senha"}</button>
              <button className="access-text-button" type="button" onClick={() => setShowConfirmPassword((v) => !v)}>{showConfirmPassword ? "Ocultar repetição" : "Mostrar repetição"}</button>
            </div>
            <button className="access-primary" disabled={busy || !actionToken}>{busy ? "Ativando..." : "Ativar acesso"}</button>
          </form>
        ) : null}

        {mode === "reset" ? (
          <form className="access-step" onSubmit={submitReset}>
            <span>NOVA SENHA</span><h2>Defina uma nova senha.</h2>
            <label><span>Token</span><input value={resetToken} onChange={(e) => setResetToken(e.target.value)} autoComplete="off" /></label>
            <label><span>Nova senha</span><input value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" type={showPassword ? "text" : "password"} placeholder="Mínimo de 15 caracteres" /></label>
            <label><span>Repetir nova senha</span><input value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} autoComplete="new-password" type={showConfirmPassword ? "text" : "password"} /></label>
            <div className="access-inline-actions">
              <button className="access-text-button" type="button" onClick={() => setShowPassword((v) => !v)}>{showPassword ? "Ocultar senha" : "Mostrar senha"}</button>
              <button className="access-text-button" type="button" onClick={() => setShowConfirmPassword((v) => !v)}>{showConfirmPassword ? "Ocultar repetição" : "Mostrar repetição"}</button>
            </div>
            <button className="access-primary" disabled={busy}>{busy ? "Redefinindo..." : "Redefinir senha"}</button>
          </form>
        ) : null}

        {mode === "register" && step === "code" ? (
          <form className="access-step" onSubmit={submitCode}>
            <span>ETAPA 1 DE 3</span><h2>Informe seu código de acesso.</h2>
            <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" placeholder="Código de acesso" />
            <button className="access-primary" disabled={busy}>{busy ? "Validando..." : "Validar código"}</button>
          </form>
        ) : null}

        {mode === "register" && step === "cocreator" ? (
          <form className="access-step" onSubmit={submitName}>
            <span>ETAPA 2 DE 3</span><h2>Dê um nome ao seu Co-Criador.</h2>
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={64} placeholder="Ex.: Atlas, Sophia, Nexo..." />
            <button className="access-primary">Continuar</button>
          </form>
        ) : null}

        {mode === "register" && step === "objective" ? (
          <div className="access-step">
            <span>ETAPA 3 DE 3</span><h2>O que vocês vão cocriar primeiro?</h2>
            <div className="access-goals">{GOALS.map((item) => (
              <button key={item} type="button" className={goal === item ? "selected" : ""} onClick={() => setGoal(item)}>{item}</button>
            ))}</div>
            <button type="button" className="access-primary" disabled={!goal} onClick={continueToIdentity}>Continuar para credencial</button>
          </div>
        ) : null}

        {mode === "register" && step === "credentials" ? (
          <form className="access-step" onSubmit={submitRegister}>
            <span>CREDENCIAL PATROAI</span><h2>Crie sua credencial segura.</h2>
            <label><span>Nome</span><input value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" /></label>
            <label><span>E-mail</span><input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" inputMode="email" /></label>
            <label><span>Senha</span><input value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" type={showPassword ? "text" : "password"} placeholder="Mínimo de 15 caracteres" /></label>
            <label><span>Repetir senha</span><input value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} autoComplete="new-password" type={showConfirmPassword ? "text" : "password"} /></label>
            <div className="access-inline-actions">
              <button className="access-text-button" type="button" onClick={() => setShowPassword((v) => !v)}>{showPassword ? "Ocultar senha" : "Mostrar senha"}</button>
              <button className="access-text-button" type="button" onClick={() => setShowConfirmPassword((v) => !v)}>{showConfirmPassword ? "Ocultar repetição" : "Mostrar repetição"}</button>
            </div>
            <button className="access-primary" disabled={busy}>{busy ? "Criando conta..." : "Criar conta"}</button>
          </form>
        ) : null}

        {error ? <p className="access-error" role="alert">{error}</p> : null}
      </section>
    </main>
  );
}
