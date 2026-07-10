import React, { useEffect, useRef, useState } from "react";

const initialActivity = [
  { hash: "0x8A1F...2C9D", date: "01/07/2026 14:32", status: "Assinado", detail: "Contrato de parceria" },
  { hash: "0x4B7E...91FA", date: "30/06/2026 09:15", status: "Assinado", detail: "Termo de confidencialidade" },
  { hash: "0x22C3...7D11", date: "29/06/2026 18:48", status: "Pendente", detail: "Proposta comercial" },
];

const navItems = ["Dashboard", "Security & 2FA", "Public Verification"];
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;
const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

export default function MainDashboard() {
  const canvasRef = useRef(null);
  const signatureSectionRef = useRef(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [authMode, setAuthMode] = useState("login");
  const [isLoading, setIsLoading] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [activeNav, setActiveNav] = useState("Dashboard");
  const [xCoordinate, setXCoordinate] = useState(120);
  const [yCoordinate, setYCoordinate] = useState(80);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [uploadedFile, setUploadedFile] = useState(null);
  const [signatureCount, setSignatureCount] = useState(12);
  const [activity, setActivity] = useState(initialActivity);
  const [statusMessage, setStatusMessage] = useState("Pronto para validar sua próxima assinatura digital.");
  const [authError, setAuthError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [isDrawing, setIsDrawing] = useState(false);
  const [signatureSaved, setSignatureSaved] = useState(false);
  const [signaturePreview, setSignaturePreview] = useState(null);
  const [verificationFile, setVerificationFile] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [accessToken, setAccessToken] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [qrCodeImage, setQrCodeImage] = useState(null);
  const [qrCodeSecret, setQrCodeSecret] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [signedPdfUrl, setSignedPdfUrl] = useState(null);
  const [signedPdfName, setSignedPdfName] = useState("");
  const [refreshingSession, setRefreshingSession] = useState(false);
  const [allSessions, setAllSessions] = useState([]);
  const [showActiveSessions, setShowActiveSessions] = useState(false);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [passkeyDevices, setPasskeyDevices] = useState([]);
  const [loadingPasskeys, setLoadingPasskeys] = useState(false);
  const [passkeyMessage, setPasskeyMessage] = useState("");

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d");
    context.lineCap = "round";
    context.lineJoin = "round";
    context.lineWidth = 2;
    context.strokeStyle = "#00E676";
  }, []);

  useEffect(() => {
    const restore = async () => {
      try {
        await refreshSession();
      } catch (error) {
        // Ignore initial restore failures; o usuário pode não ter sessão válida.
      }
    };
    restore();
  }, []);

  useEffect(() => {
    return () => {
      if (signedPdfUrl) {
        window.URL.revokeObjectURL(signedPdfUrl);
      }
    };
  }, [signedPdfUrl]);

  const resetAuthForm = () => {
    setName("");
    setEmail("");
    setPassword("");
    setConfirmPassword("");
    setTotpCode("");
  };

  const getCanvasPoint = (event) => {
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const clientX = event.touches ? event.touches[0].clientX : event.clientX;
    const clientY = event.touches ? event.touches[0].clientY : event.clientY;
    return { x: clientX - rect.left, y: clientY - rect.top };
  };

  const startDrawing = (event) => {
    event.preventDefault();
    const { x, y } = getCanvasPoint(event);
    const context = canvasRef.current.getContext("2d");
    context.beginPath();
    context.moveTo(x, y);
    setIsDrawing(true);
  };

  const draw = (event) => {
    if (!isDrawing) return;
    event.preventDefault();
    const { x, y } = getCanvasPoint(event);
    const context = canvasRef.current.getContext("2d");
    context.lineTo(x, y);
    context.stroke();
  };

  const stopDrawing = () => {
    setIsDrawing(false);
  };

  const clearSignature = () => {
    const canvas = canvasRef.current;
    const context = canvas.getContext("2d");
    context.clearRect(0, 0, canvas.width, canvas.height);
    setSignaturePreview(null);
    setSignatureSaved(false);
    setStatusMessage("Área de assinatura limpa.");
  };

  const saveSignature = () => {
    const dataUrl = canvasRef.current.toDataURL("image/png");
    setSignaturePreview(dataUrl);
    setSignatureSaved(true);
    setStatusMessage("Assinatura salva e vinculada ao documento.");
  };

  const getCsrfTokenFromCookie = () => {
    const match = document.cookie.match(/(^|;)\s*csrf_token=([^;]+)/);
    return match ? decodeURIComponent(match[2]) : "";
  };

  const apiFetch = async (path, options = {}) => {
    const isFormData = options.body instanceof FormData;
    const defaultHeaders = isFormData ? {} : { "Content-Type": "application/json" };
    const authHeaders = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
    const csrfTokenValue = csrfToken || getCsrfTokenFromCookie();
    const csrfHeaders = csrfTokenValue ? { "X-CSRF-Token": csrfTokenValue } : {};
    const headers = { ...defaultHeaders, ...authHeaders, ...csrfHeaders, ...(options.headers || {}) };
    const response = await fetch(`${API_BASE}${path}`, {
      credentials: "include",
      ...options,
      headers,
    });

    const text = await response.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }

    const isRetryable =
      response.status === 401 &&
      accessToken &&
      !["/auth/refresh", "/auth/logout", "/auth/login", "/auth/register", "/auth/totp/setup", "/auth/totp/enable"].includes(path);

    if (isRetryable) {
      try {
        await refreshSession();
        return apiFetch(path, options);
      } catch (retryError) {
        throw body || new Error(response.statusText);
      }
    }

    if (!response.ok) {
      throw body || new Error(response.statusText);
    }

    return body;
  };

  const bufferToBase64Url = (value) => {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  const base64UrlToBuffer = (value) => {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4;
    const padded = padding === 0 ? normalized : normalized + "=".repeat(4 - padding);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  };

  const buildPublicKeyOptions = (options) => ({
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: options.user ? { ...options.user, id: base64UrlToBuffer(options.user.id) } : undefined,
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: base64UrlToBuffer(credential.id),
    })),
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: base64UrlToBuffer(credential.id),
    })),
  });

  const loadPasskeyDevices = async () => {
    if (!accessToken) return;
    try {
      setLoadingPasskeys(true);
      const response = await apiFetch("/auth/webauthn/devices", { method: "GET" });
      setPasskeyDevices(response.devices || []);
    } catch (error) {
      setPasskeyMessage(error?.detail?.message || error?.message || "Falha ao carregar dispositivos passkey.");
    } finally {
      setLoadingPasskeys(false);
    }
  };

  const registerPasskey = async () => {
    if (!window.PublicKeyCredential || !navigator.credentials?.create) {
      setPasskeyMessage("Seu navegador não suporta Passkeys/WebAuthn.");
      return;
    }

    try {
      setPasskeyMessage("");
      const options = await apiFetch("/auth/webauthn/register/generate", { method: "POST" });
      const credential = await navigator.credentials.create({
        publicKey: buildPublicKeyOptions(options),
      });

      const response = credential.response;
      const payload = {
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64Url(response.clientDataJSON),
          attestationObject: bufferToBase64Url(response.attestationObject),
          transports: response.transports || [],
        },
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      };

      await apiFetch("/auth/webauthn/register/verify", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      setPasskeyMessage("Passkey registrada com sucesso.");
      await loadPasskeyDevices();
    } catch (error) {
      setPasskeyMessage(error?.detail?.message || error?.message || "Falha ao registrar a Passkey.");
    }
  };

  const loginWithPasskey = async () => {
    if (!window.PublicKeyCredential || !navigator.credentials?.get) {
      setAuthError("Seu navegador não suporta Passkeys/WebAuthn.");
      return;
    }

    if (!email.trim()) {
      setAuthError("Informe o e-mail ou nome de usuário para continuar com Passkey.");
      return;
    }

    try {
      setAuthError("");
      setSuccessMessage("");
      setIsLoading(true);
      const options = await apiFetch("/auth/webauthn/authenticate/generate", {
        method: "POST",
        body: JSON.stringify({ username: email.trim().toLowerCase() }),
      });
      const credential = await navigator.credentials.get({
        publicKey: buildPublicKeyOptions(options),
      });

      const response = credential.response;
      const payload = {
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64Url(response.clientDataJSON),
          authenticatorData: bufferToBase64Url(response.authenticatorData),
          signature: bufferToBase64Url(response.signature),
          userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
        },
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      };

      const data = await apiFetch("/auth/webauthn/authenticate/verify", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      setAccessToken(data.access_token);
      setCsrfToken(data.csrf_token || "");
      setCurrentUser(
        data.user
          ? {
              id: data.user.id,
              username: data.user.username,
              email: data.user.email,
              name: data.user.username,
              is_totp_enabled: data.user.is_totp_enabled,
            }
          : {
              username: email.trim().toLowerCase(),
              email: email.trim().toLowerCase(),
              name: email.trim().toLowerCase(),
              is_totp_enabled: false,
            }
      );
      setIsAuthenticated(true);
      setTwoFactorRequired(false);
      setTotpCode("");
      setSuccessMessage("Login com Passkey concluído com sucesso.");
      setStatusMessage(`Bem-vindo, ${email.trim().toLowerCase()}.`);
      setActiveNav("Dashboard");
      setTimeout(() => signatureSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }), 250);
      await loadPasskeyDevices();
    } catch (error) {
      setAuthError(error?.detail?.message || error?.message || "Falha ao autenticar com Passkey.");
    } finally {
      setIsLoading(false);
    }
  };

  const revokePasskeyDevice = async (deviceId) => {
    try {
      await apiFetch(`/auth/webauthn/devices/${deviceId}`, { method: "DELETE" });
      setPasskeyDevices((current) => current.filter((device) => device.id !== deviceId));
      setPasskeyMessage("Dispositivo removido com sucesso.");
    } catch (error) {
      setPasskeyMessage(error?.detail?.message || error?.message || "Falha ao remover o dispositivo.");
    }
  };

  const handleChangePassword = async (event) => {
    event.preventDefault();
    setAuthError("");
    setSuccessMessage("");

    if (!oldPassword.trim() || !newPassword.trim() || !confirmNewPassword.trim()) {
      setAuthError("Preencha a senha atual, a nova senha e a confirmação.");
      return;
    }

    if (!passwordRegex.test(newPassword)) {
      setAuthError("A nova senha deve ter pelo menos 12 caracteres, com maiúsculas, minúsculas, número e símbolo.");
      return;
    }

    if (newPassword !== confirmNewPassword) {
      setAuthError("A confirmação da nova senha não confere.");
      return;
    }

    try {
      await apiFetch("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
        }),
      });
      setSuccessMessage("Senha alterada com sucesso. Todas as sessões foram encerradas por segurança.");
      setOldPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setShowChangePassword(false);
    } catch (error) {
      setAuthError(error?.detail?.message || error?.message || "Falha ao alterar a senha.");
    }
  };

  const refreshSession = async () => {
    if (refreshingSession) return;
    setRefreshingSession(true);

    try {
      const csrfTokenValue = csrfToken || getCsrfTokenFromCookie();
      const data = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          ...(csrfTokenValue ? { "X-CSRF-Token": csrfTokenValue } : {}),
        },
      });

      if (!data.ok) {
        throw new Error("Sessão não restaurada");
      }

      const body = await data.json();
      setAccessToken(body.access_token || "");
      setCsrfToken(body.csrf_token || "");
      if (body.user) {
        setCurrentUser({
          id: body.user.id,
          username: body.user.username,
          email: body.user.email,
          name: body.user.username,
          is_totp_enabled: body.user.is_totp_enabled,
        });
        setIsAuthenticated(true);
        setStatusMessage(`Sessão restaurada. Bem-vindo de volta, ${body.user.username}.`);
        await loadPasskeyDevices();
      }

      return body;
    } finally {
      setRefreshingSession(false);
    }
  };

  const handleAuthSubmit = async (event) => {
    event.preventDefault();
    setAuthError("");
    setSuccessMessage("");
    setIsLoading(true);

    if (!email.trim() || !password.trim()) {
      setAuthError("Informe e-mail e senha.");
      setIsLoading(false);
      return;
    }

    if (authMode === "register") {
      if (!name.trim()) {
        setAuthError("Informe seu nome completo.");
        setIsLoading(false);
        return;
      }
      if (!email.includes("@") || !email.includes(".")) {
        setAuthError("Informe um e-mail válido.");
        setIsLoading(false);
        return;
      }
      if (!passwordRegex.test(password)) {
        setAuthError("A senha deve ter pelo menos 12 caracteres, com maiúsculas, minúsculas, número e símbolo.");
        setIsLoading(false);
        return;
      }
      if (password !== confirmPassword) {
        setAuthError("As senhas não conferem.");
        setIsLoading(false);
        return;
      }

      try {
        const payload = {
          username: email.trim().toLowerCase(),
          email: email.trim().toLowerCase(),
          password,
        };

        const data = await apiFetch("/auth/register", {
          method: "POST",
          body: JSON.stringify(payload),
        });

        setAuthMode("login");
        setSuccessMessage("Conta criada com sucesso. Faça login para continuar.");
        setEmail(email.trim().toLowerCase());
        setPassword("");
        setConfirmPassword("");
      } catch (error) {
        setAuthError(error?.detail?.message || error?.message || "Falha ao registrar usuário.");
      } finally {
        setIsLoading(false);
      }
      return;
    }

    try {
      const payload = {
        username: email.trim().toLowerCase(),
        password,
      };
      if (totpCode.trim()) {
        payload.totp_code = totpCode.trim();
      }

      const data = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      setAccessToken(data.access_token);
      setCsrfToken(data.csrf_token || "");
      setCurrentUser(
        data.user
          ? {
              id: data.user.id,
              username: data.user.username,
              email: data.user.email,
              name: data.user.username,
              is_totp_enabled: data.user.is_totp_enabled,
            }
          : {
              username: email.trim().toLowerCase(),
              email: email.trim().toLowerCase(),
              name: email.trim().toLowerCase(),
              is_totp_enabled: false,
            }
      );
      setIsAuthenticated(true);
      setTwoFactorRequired(false);
      setTotpCode("");
      setSuccessMessage("Login concluído com sucesso.");
      setStatusMessage(`Bem-vindo, ${email.trim().toLowerCase()}.`);
      setActiveNav("Dashboard");
      // scroll to signature area after login
      setTimeout(() => signatureSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }), 250);
      await loadPasskeyDevices();
    } catch (error) {
      const detail = error?.code || error?.detail?.code || error?.detail || error?.message || "Falha ao efetuar login.";
      if (detail === "AUTH_003" || (error?.detail && error.detail.message === "Código 2FA inválido")) {
        setTwoFactorRequired(true);
        setSuccessMessage("Código TOTP necessário para concluir o login.");
        setAuthError("");
      } else {
        setAuthError(error?.detail?.message || error?.message || "Credenciais inválidas.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleTotpSetup = async () => {
    if (!accessToken) {
      setStatusMessage("Faça login para configurar o TOTP.");
      return;
    }

    try {
      const data = await apiFetch("/auth/totp/setup", { method: "POST" });
      setQrCodeSecret(data.secret || "");
      setQrCodeImage(data.qr_code_image || null);
      setBackupCodes(data.backup_codes || []);
      setSuccessMessage("QR code TOTP gerado. Escaneie com Authy, Microsoft Authenticator ou similar.");
    } catch (error) {
      setAuthError(error?.detail?.message || error?.message || "Falha ao gerar QR code TOTP.");
    }
  };

  const handleTotpEnable = async () => {
    if (!accessToken) {
      setStatusMessage("Faça login para habilitar o TOTP.");
      return;
    }
    if (!totpCode.trim()) {
      setStatusMessage("Informe o código TOTP do app.");
      return;
    }

    try {
      await apiFetch("/auth/totp/enable", {
        method: "POST",
        body: JSON.stringify({ totp_code: totpCode.trim() }),
      });
      setSuccessMessage("Autenticação de dois fatores habilitada com sucesso.");
      setTwoFactorRequired(false);
      setTotpCode("");
      setCurrentUser((current) => current ? { ...current, is_totp_enabled: true } : current);
    } catch (error) {
      setAuthError(error?.detail?.message || error?.message || "Falha ao habilitar TOTP.");
    }
  };

  const handleLogout = async () => {
    try {
      await apiFetch("/auth/logout", { method: "POST" });
    } catch {
      // ignore logout errors; limpa localmente mesmo se backend falhar
    }
    setIsAuthenticated(false);
    setCurrentUser(null);
    setTwoFactorRequired(false);
    setAccessToken("");
    setCsrfToken("");
    setQrCodeImage(null);
    setQrCodeSecret("");
    setBackupCodes([]);
    resetAuthForm();
    setStatusMessage("Sessão encerrada. Faça login para continuar.");
  };

  // REQ-57: Gerenciamento de Sessões Ativas
  const loadActiveSessions = async () => {
    try {
      setLoadingSessions(true);
      const response = await apiFetch("/auth/sessions", { method: "GET" });
      setAllSessions(response.sessions || []);
      setShowActiveSessions(true);
      setStatusMessage("✓ Sessões ativas carregadas");
    } catch (error) {
      setAuthError(`Erro ao carregar sessões: ${error?.detail?.message || error?.message}`);
    } finally {
      setLoadingSessions(false);
    }
  };

  const revokeSpecificSession = async (sessionId) => {
    try {
      await apiFetch(`/auth/sessions/${sessionId}/revoke`, { method: "POST" });
      setAllSessions((current) => current.filter((s) => s.id !== sessionId));
      setStatusMessage("✓ Sessão encerrada com sucesso");
    } catch (error) {
      setAuthError(`Erro ao revogar sessão: ${error?.detail?.message || error?.message}`);
    }
  };

  const revokeAllSessions = async () => {
    try {
      if (!confirm("Tem certeza? Isso encerrará todas as suas outras sessões.")) return;
      await apiFetch("/auth/sessions/revoke-all", { method: "POST" });
      setAllSessions([]);
      setStatusMessage("✓ Todas as outras sessões foram encerradas");
    } catch (error) {
      setAuthError(`Erro ao revogar sessões: ${error?.detail?.message || error?.message}`);
    }
  };

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];
    if (file) {
      // REQ-61: Validar tamanho máximo de 20MB
      const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB em bytes
      if (file.size > MAX_FILE_SIZE) {
        setStatusMessage(`❌ Arquivo excede o limite de 20MB (tamanho atual: ${(file.size / 1024 / 1024).toFixed(2)}MB)`);
        setAuthError("O arquivo é muito grande. O limite máximo é 20MB.");
        return;
      }
      setUploadedFile(file);
      setSignedPdfUrl(null);
      setSignedPdfName("");
      setStatusMessage(`✓ Arquivo selecionado: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)}MB)`);
      setAuthError(""); // Limpar erros anteriores
      setActivity((current) => [
        { hash: "0xNEW...1A2B", date: new Date().toLocaleString("pt-BR"), status: "Em análise", detail: file.name },
        ...current.slice(0, 2),
      ]);
    }
  };

  const handleSign = async () => {
    if (!signatureSaved) {
      setStatusMessage("Desenhe e salve sua assinatura antes de assinar o documento.");
      return;
    }
    if (!uploadedFile) {
      setStatusMessage("Selecione um arquivo PDF antes de assinar.");
      return;
    }

    setIsSigning(true);
    setStatusMessage("Enviando documento para assinatura no servidor...");

    try {
      const headers = {};
      if (accessToken) {
        headers.Authorization = `Bearer ${accessToken}`;
      }
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken;
      }

      const formData = new FormData();
      formData.append("file", uploadedFile);
      formData.append("coord_x", String(xCoordinate));
      formData.append("coord_y", String(yCoordinate));

      const response = await fetch(`${API_BASE}/pdf/sign`, {
        method: "POST",
        credentials: "include",
        headers,
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || "Falha na assinatura do servidor.");
      }

      const signedPdfBlob = await response.blob();
      const signedPdfUrlValue = window.URL.createObjectURL(signedPdfBlob);
      setSignedPdfUrl(signedPdfUrlValue);
      setSignedPdfName(`assinado-${(uploadedFile.name || "documento.pdf").replace(/\.pdf$/i, "")}.pdf`);
      setSignatureCount((count) => count + 1);
      setActivity((current) => [
        {
          hash: `0x${Math.random().toString(16).slice(2, 8).toUpperCase()}...`,
          date: new Date().toLocaleString("pt-BR"),
          status: "Assinado",
          detail: uploadedFile?.name || "Documento PDF",
        },
        ...current.slice(0, 2),
      ]);
      setStatusMessage("Documento assinado com sucesso pelo servidor. PDF pronto para download.");
    } catch (error) {
      console.error(error);
      setStatusMessage("Falha ao assinar o documento. Tente novamente.");
    } finally {
      setIsSigning(false);
    }
  };

  const handleDownloadPdf = () => {
    if (!signedPdfUrl) {
      setStatusMessage("Assine o documento primeiro para gerar o PDF baixável.");
      return;
    }

    const link = document.createElement("a");
    link.href = signedPdfUrl;
    link.download = signedPdfName || "documento-assinado.pdf";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setStatusMessage(`Download iniciado para ${signedPdfName || "documento-assinado.pdf"}.`);
  };

  const handleRegenerate2FA = () => {
    if (!accessToken) {
      setStatusMessage("Faça login para acessar as configurações de 2FA.");
      return;
    }
    setStatusMessage("O aplicativo de autenticação deve gerar o código. Use a função TOTP no seu Authenticator móvel.");
  };

  const handleVerify = async () => {
    if (!verificationFile) {
      setVerificationResult(null);
      setStatusMessage("Selecione um PDF para verificar a assinatura.");
      return;
    }

    setStatusMessage("Enviando arquivo para verificação...");

    try {
      const headers = {};
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken;
      }

      const formData = new FormData();
      formData.append("file", verificationFile);

      const response = await fetch(`${API_BASE}/pdf/verify`, {
        method: "POST",
        credentials: "include",
        headers,
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || "Falha ao verificar o documento.");
      }

      const data = await response.json();
      setVerificationResult({
        hash: data.original_hash || "-",
        status: data.status || "VALID",
        detail: data.message || "Documento verificado com sucesso.",
        date: data.signed_at || new Date().toLocaleString("pt-BR"),
        verified: true,
      });
      setStatusMessage("Verificação concluída com sucesso.");
    } catch (error) {
      console.error(error);
      setVerificationResult({
        hash: verificationFile.name,
        status: "Não verificado",
        detail: error.message || "Falha na verificação.",
        date: "-",
        verified: false,
      });
      setStatusMessage("Falha ao verificar o documento. Verifique o PDF ou tente novamente.");
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0D1117] px-4 py-10 text-slate-100 sm:px-6 lg:px-8">
        <div className="mx-auto flex max-w-6xl flex-col overflow-hidden rounded-3xl border border-gray-800 bg-[#161B22]/90 shadow-[0_0_60px_rgba(0,0,0,0.35)] lg:flex-row">
          <div className="flex-1 bg-[radial-gradient(circle_at_top_left,_rgba(0,230,118,0.2),_transparent_35%)] p-8 sm:p-10 lg:p-12">
            <div className="mb-8 flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-emerald-400/30 bg-emerald-500/10 text-xl font-semibold text-[#00E676]">
                S
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.35em] text-emerald-400/80">SecureSign</p>
                <h1 className="text-2xl font-semibold text-white">Acesso seguro ao painel</h1>
              </div>
            </div>
            <h2 className="max-w-xl text-3xl font-semibold text-white sm:text-4xl">
              Assine documentos com rastreabilidade, confiança e auditoria completa.
            </h2>
            <p className="mt-4 max-w-xl text-base text-slate-400">
              Crie uma conta ou entre com suas credenciais para acessar a área protegida.
            </p>
            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              {[
                { label: "Criptografia", value: "256-bit" },
                { label: "Hash", value: "Auditável" },
                { label: "Tempo", value: "< 2s" },
              ].map((item) => (
                <div key={item.label} className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <p className="text-xs uppercase tracking-[0.25em] text-slate-500">{item.label}</p>
                  <p className="mt-2 text-lg font-semibold text-[#00E676]">{item.value}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="w-full border-t border-gray-800 bg-[#0D1117]/90 p-8 sm:p-10 lg:w-[460px] lg:border-l lg:border-t-0 lg:px-10 lg:py-12">
            <form onSubmit={handleAuthSubmit} className="space-y-6">
              <div className="mb-8">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <p className="text-xs uppercase tracking-[0.35em] text-emerald-400">{authMode === "login" ? "Acesso" : "Cadastro"}</p>
                    <h3 className="mt-3 text-3xl font-semibold text-white">{authMode === "login" ? "Entrar na conta" : "Criar conta"}</h3>
                  </div>
                  <div className="inline-flex overflow-hidden rounded-full border border-gray-800 bg-[#161B22]/70 p-1 shadow-[0_10px_30px_rgba(0,0,0,0.15)]">
                    <button
                      type="button"
                      onClick={() => {
                        setAuthMode("login");
                        setAuthError("");
                        setSuccessMessage("");
                        resetAuthForm();
                      }}
                      className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                        authMode === "login"
                          ? "bg-emerald-500/15 text-emerald-200"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >
                      Entrar
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAuthMode("register");
                        setAuthError("");
                        setSuccessMessage("");
                        resetAuthForm();
                      }}
                      className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                        authMode === "register"
                          ? "bg-emerald-500/15 text-emerald-200"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >
                      Criar conta
                    </button>
                  </div>
                </div>
              </div>

              {authMode === "register" && (
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">Nome</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    className="w-full rounded-3xl border border-gray-800 bg-[#161B22] px-4 py-4 text-sm text-white outline-none transition duration-200 focus:border-emerald-400/50"
                    placeholder="Seu nome completo"
                    required
                  />
                </div>
              )}

              <div>
                <label className="mb-2 block text-sm font-medium text-slate-300">E-mail</label>
                <input
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="w-full rounded-3xl border border-gray-800 bg-[#161B22] px-4 py-4 text-sm text-white outline-none transition duration-200 focus:border-emerald-400/50"
                  placeholder="seu@email.com"
                  required
                />
              </div>

              <div>
                <label className="mb-2 block text-sm font-medium text-slate-300">Senha</label>
                <input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="w-full rounded-3xl border border-gray-800 bg-[#161B22] px-4 py-4 text-sm text-white outline-none transition duration-200 focus:border-emerald-400/50"
                  placeholder="Sua senha"
                  required
                />
              </div>

              {authMode === "register" && (
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">Confirmar senha</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    className="w-full rounded-3xl border border-gray-800 bg-[#161B22] px-4 py-4 text-sm text-white outline-none transition duration-200 focus:border-emerald-400/50"
                    placeholder="Repita a senha"
                    required
                  />
                </div>
              )}

              {authMode === "login" && twoFactorRequired && (
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">Código TOTP</label>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.target.value)}
                    className="w-full rounded-3xl border border-gray-800 bg-[#161B22] px-4 py-4 text-sm text-white outline-none transition duration-200 focus:border-emerald-400/50"
                    placeholder="123456"
                    required
                  />
                </div>
              )}

              {authError && <p className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">{authError}</p>}
              {successMessage && <p className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-3 text-sm text-emerald-200">{successMessage}</p>}

              {authMode === "login" && (
                <button
                  type="button"
                  onClick={loginWithPasskey}
                  disabled={isLoading}
                  className="flex w-full items-center justify-center gap-2 rounded-3xl border border-blue-400/30 bg-blue-500/10 px-4 py-4 text-sm font-semibold text-blue-300 transition hover:bg-blue-500/20 disabled:cursor-not-allowed disabled:opacity-80"
                >
                  {isLoading ? "Aguarde..." : "Entrar com Passkey"}
                </button>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="mt-2 flex w-full items-center justify-center gap-2 rounded-3xl border border-emerald-400/30 bg-[#00E676] px-4 py-4 text-base font-semibold text-[#04110A] transition duration-200 hover:shadow-[0_0_25px_rgba(0,230,118,0.3)] disabled:cursor-not-allowed disabled:opacity-80"
              >
                {isLoading ? (
                  <>
                    <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" className="opacity-25" />
                      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="opacity-80" />
                    </svg>
                    {authMode === "login" ? "Entrando..." : "Cadastrando..."}
                  </>
                ) : authMode === "login" ? (
                  "Entrar"
                ) : (
                  "Criar conta"
                )}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0D1117] text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col lg:flex-row">
        <aside className="w-full border-b border-gray-800 bg-[#0D1117]/80 px-4 py-6 backdrop-blur-xl lg:w-72 lg:border-b-0 lg:border-r lg:px-6 lg:pt-8">
          <div className="mb-8 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-400/30 bg-emerald-500/10 text-lg font-semibold text-[#00E676]">
              S
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.35em] text-emerald-400/80">SecureSign</p>
              <h2 className="text-lg font-semibold text-white">Painel Central</h2>
            </div>
          </div>

          <nav className="space-y-2">
            {navItems.map((item, index) => {
              const isActive = item === activeNav;
              return (
                <button
                  key={item}
                  onClick={() => setActiveNav(item)}
                  className={`flex w-full items-center justify-between rounded-xl px-4 py-3 text-left text-sm font-medium transition-all ${
                    isActive
                      ? "border border-emerald-400/30 bg-[#08231F] text-[#00E676] shadow-[0_0_25px_rgba(0,230,118,0.18)]"
                      : "border border-transparent bg-transparent text-slate-300 hover:border-gray-700 hover:bg-[#161B22]"
                  }`}
                >
                  <span>{item}</span>
                  <span className="text-xs text-slate-500">0{index + 1}</span>
                </button>
              );
            })}
          </nav>

          <div className="mt-8 rounded-[28px] border border-gray-800 bg-[#161B22]/80 p-4 shadow-[0_0_30px_rgba(0,0,0,0.25)]">
            <p className="text-xs uppercase tracking-[0.29em] text-slate-500">Status do sistema</p>
            <div className="mt-3 flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#00E676] shadow-[0_0_8px_#00E676]" />
              <span className="text-sm text-slate-200">Opera��o segura online</span>
            </div>
            <p className="mt-3 text-sm text-slate-400">Assinaturas criptogr�ficas protegidas por certificados v�lidos.</p>
          </div>
        </aside>

        <main className="flex-1 p-4 sm:p-6 lg:p-8">
          <header className="mb-6 flex flex-col gap-4 rounded-[32px] border border-gray-800 bg-[#121A23]/90 p-6 shadow-[0_0_40px_rgba(0,0,0,0.26)] backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-medium text-emerald-400">Dashboard principal</p>
              <h1 className="text-3xl font-semibold text-white sm:text-4xl">Assinatura digital de documentos</h1>
              <p className="mt-2 text-sm text-slate-400">{statusMessage}</p>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-3 rounded-xl border border-gray-800 bg-[#0D1117]/80 px-3 py-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/15 text-sm font-semibold text-[#00E676]">
                  {currentUser?.name?.split(" ").filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "US"}
                </div>
                <div className="text-left">
                  <p className="text-sm font-medium text-white">{currentUser?.name || "Usu�rio"}</p>
                  <p className="text-xs text-slate-400">{currentUser?.role || "Acesso seguro"}</p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-[#00E676] transition hover:bg-emerald-500/20 hover:shadow-[0_0_20px_rgba(0,230,118,0.2)]"
              >
                Sair
              </button>
            </div>
          </header>

          <section className="mb-6 grid gap-4 md:grid-cols-3">
            {[
              { label: "Assinaturas hoje", value: signatureCount },
              { label: "Arquivo carregado", value: uploadedFile ? "Sim" : "Aguardando" },
              { label: "Seção ativa", value: activeNav },
            ].map((item) => (
              <div key={item.label} className="rounded-[32px] border border-gray-800 bg-[#0B1218]/85 p-5 shadow-[0_0_35px_rgba(0,0,0,0.16)] backdrop-blur-xl">
                <p className="text-sm uppercase tracking-[0.25em] text-slate-500">{item.label}</p>
                <p className="mt-3 text-3xl font-semibold text-white">{item.value}</p>
              </div>
            ))}
          </section>

          {activeNav === "Security & 2FA" && (
            <section className="mb-6 rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)]">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Segurança</p>
                  <h2 className="text-xl font-semibold text-white">Autenticação de dois fatores</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    O fluxo exige um código TOTP após a senha e usa a configuração de QR code fornecida pelo servidor.
                  </p>
                </div>
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                  <p className="font-semibold">TOTP habilitado</p>
                  <p className="mt-1 text-emerald-100/80">{currentUser?.is_totp_enabled ? "Sim" : "Não"}</p>
                </div>
              </div>
            </section>
          )}

          {activeNav === "Security & 2FA" ? (
            <section className="mb-6 rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)]">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="max-w-2xl">
                  <p className="text-sm font-medium text-emerald-400">Segurança</p>
                  <h2 className="text-xl font-semibold text-white">Autenticação de dois fatores atualizada</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    O fluxo mostra o estado da autenticação, permite gerar um novo código TOTP e reforça a proteção do acesso.
                  </p>
                </div>
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                  <p className="font-semibold">TOTP habilitado</p>
                  <p className="mt-1 text-emerald-100/80">{currentUser?.is_totp_enabled ? "Sim" : "Não"}</p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <h3 className="text-lg font-semibold text-white">Status da autenticação</h3>
                  <ul className="mt-4 space-y-3 text-sm text-slate-400">
                    <li>• Login protegido por senha e verificação adicional.</li>
                    <li>• O TOTP é configurado no servidor e verificado durante o login.</li>
                    <li>• O aplicativo de autenticação do usuário gera códigos válidos de 30 segundos.</li>
                  </ul>
                </div>
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <h3 className="text-lg font-semibold text-white">Ações rápidas</h3>
                  <button
                    type="button"
                    onClick={handleTotpSetup}
                    className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300"
                  >
                    Gerar QR code TOTP
                  </button>
                  <div className="mt-4">
                    <label className="mb-2 block text-sm font-medium text-slate-300">Código TOTP</label>
                    <input
                      type="text"
                      value={totpCode}
                      onChange={(event) => setTotpCode(event.target.value)}
                      className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                      placeholder="123456"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={handleTotpEnable}
                    className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300"
                  >
                    Habilitar TOTP
                  </button>
                  <p className="mt-3 text-sm text-slate-400">
                    Depois de escanear o QR code, insira o código do app para habilitar a autenticação de dois fatores.
                  </p>
                  <button
                    type="button"
                    onClick={() => setShowChangePassword((current) => !current)}
                    className="mt-4 rounded-xl border border-amber-400/30 bg-amber-500/10 px-4 py-2 text-sm font-semibold text-amber-300"
                  >
                    {showChangePassword ? "Fechar alteração de senha" : "Alterar senha"}
                  </button>
                </div>
              </div>

              {showChangePassword && (
                <form onSubmit={handleChangePassword} className="mt-6 rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <h3 className="text-lg font-semibold text-white">Alterar senha</h3>
                  <div className="mt-4 grid gap-4 lg:grid-cols-3">
                    <div>
                      <label className="mb-2 block text-sm font-medium text-slate-300">Senha atual</label>
                      <input
                        type="password"
                        value={oldPassword}
                        onChange={(event) => setOldPassword(event.target.value)}
                        className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                      />
                    </div>
                    <div>
                      <label className="mb-2 block text-sm font-medium text-slate-300">Nova senha</label>
                      <input
                        type="password"
                        value={newPassword}
                        onChange={(event) => setNewPassword(event.target.value)}
                        className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                      />
                    </div>
                    <div>
                      <label className="mb-2 block text-sm font-medium text-slate-300">Confirmar nova senha</label>
                      <input
                        type="password"
                        value={confirmNewPassword}
                        onChange={(event) => setConfirmNewPassword(event.target.value)}
                        className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                      />
                    </div>
                  </div>
                  <button
                    type="submit"
                    className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300"
                  >
                    Confirmar alteração
                  </button>
                </form>
              )}

              <div className="mt-6 rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h3 className="text-lg font-semibold text-white">Passkeys</h3>
                    <p className="mt-2 text-sm text-slate-400">Registre e gerencie dispositivos WebAuthn para login sem senha.</p>
                  </div>
                  <button
                    type="button"
                    onClick={registerPasskey}
                    className="rounded-xl border border-blue-400/30 bg-blue-500/10 px-4 py-2 text-sm font-semibold text-blue-300"
                  >
                    Registrar Passkey
                  </button>
                </div>
                {passkeyMessage && <p className="mt-3 text-sm text-emerald-200">{passkeyMessage}</p>}
                <button
                  type="button"
                  onClick={loadPasskeyDevices}
                  disabled={loadingPasskeys}
                  className="mt-4 rounded-xl border border-gray-700 bg-[#161B22] px-4 py-2 text-sm font-semibold text-slate-300 disabled:opacity-50"
                >
                  {loadingPasskeys ? "Carregando..." : "Atualizar dispositivos"}
                </button>
                <div className="mt-4 space-y-2">
                  {passkeyDevices.length === 0 ? (
                    <p className="text-sm text-slate-400">Nenhuma Passkey registrada ainda.</p>
                  ) : (
                    passkeyDevices.map((device) => (
                      <div key={device.id} className="flex items-center justify-between rounded-lg border border-gray-700 bg-[#161B22]/60 px-3 py-2">
                        <div>
                          <p className="text-sm font-medium text-white">{device.credential_id_prefix || device.id}</p>
                          <p className="text-xs text-slate-400">Contador: {device.sign_count}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => revokePasskeyDevice(device.id)}
                          className="rounded px-3 py-1 text-xs font-semibold text-red-300 hover:bg-red-500/20"
                        >
                          Revogar
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
              {qrCodeImage && (
                <div className="mt-6 rounded-2xl border border-emerald-400/20 bg-[#0D1117]/70 p-4 text-sm text-slate-200">
                  <p className="font-semibold text-white">QR code de configuração</p>
                  <p className="mt-3 text-slate-400">Escaneie este QR code com o app Authenticator do seu dispositivo.</p>
                  <img src={qrCodeImage} alt="QR code TOTP" className="mt-4 max-w-full rounded-xl border border-gray-800 bg-white p-3" />
                  {backupCodes.length > 0 && (
                    <div className="mt-4 rounded-xl border border-gray-800 bg-[#161B22]/80 p-3 text-slate-300">
                      <p className="font-semibold text-white">Códigos de backup</p>
                      <ul className="mt-2 list-disc space-y-1 pl-5 text-slate-300">
                        {backupCodes.map((code) => (
                          <li key={code}>{code}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
              
              {/* REQ-57: Gerenciamento de Sessões Ativas */}
              <div className="mt-6 rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                <h3 className="text-lg font-semibold text-white">Gerenciamento de Sessões</h3>
                <p className="mt-2 text-sm text-slate-400">Visualize e gerencie suas sessões ativas em outros dispositivos.</p>
                <button
                  type="button"
                  onClick={loadActiveSessions}
                  disabled={loadingSessions}
                  className="mt-4 rounded-xl border border-blue-400/30 bg-blue-500/10 px-4 py-2 text-sm font-semibold text-blue-300 disabled:opacity-50"
                >
                  {loadingSessions ? "Carregando..." : "Ver Sessões Ativas"}
                </button>
              </div>
              
              {showActiveSessions && (
                <div className="mt-6 rounded-2xl border border-blue-400/20 bg-[#0D1117]/70 p-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-white">Sessões Ativas ({allSessions.length})</h3>
                    <button
                      type="button"
                      onClick={() => setShowActiveSessions(false)}
                      className="text-sm text-slate-400 hover:text-slate-200"
                    >
                      ✕ Fechar
                    </button>
                  </div>
                  <p className="mt-2 text-sm text-slate-400">Clique em uma sessão para encerrar ou use o botão abaixo para sair de todos os dispositivos.</p>
                  
                  {allSessions.length === 0 ? (
                    <p className="mt-4 text-sm text-slate-400">Nenhuma outra sessão ativa.</p>
                  ) : (
                    <div className="mt-4 space-y-2">
                      {allSessions.map((session) => (
                        <div key={session.id} className="flex items-center justify-between rounded-lg border border-gray-700 bg-[#161B22]/50 px-3 py-2">
                          <div className="flex-1">
                            <p className="text-sm font-medium text-white">{session.ip_address}</p>
                            <p className="text-xs text-slate-400">{session.user_agent?.substring(0, 40)}...</p>
                            <p className="text-xs text-slate-500">Expira: {new Date(session.expires_at).toLocaleString("pt-BR")}</p>
                          </div>
                          <button
                            type="button"
                            onClick={() => revokeSpecificSession(session.id)}
                            className="ml-2 rounded px-3 py-1 text-xs font-semibold text-red-300 hover:bg-red-500/20"
                          >
                            Encerrar
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  
                  {allSessions.length > 0 && (
                    <button
                      type="button"
                      onClick={revokeAllSessions}
                      className="mt-4 w-full rounded-xl border border-red-400/30 bg-red-500/10 px-4 py-2 text-sm font-semibold text-red-300"
                    >
                      Sair de Todos os Dispositivos
                    </button>
                  )}
                </div>
              )}
            </section>
          ) : activeNav === "Public Verification" ? (
            <section className="mb-6 rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)]">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Verificação pública</p>
                  <h2 className="text-xl font-semibold text-white">Validar assinatura digital</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    Envie o PDF para o servidor validar sua assinatura e integridade com base no histórico de registros.
                  </p>
                </div>
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                  <p className="font-semibold">Status da consulta</p>
                  <p className="mt-1 text-emerald-100/80">{verificationResult?.verified ? "Validado" : "Aguardando"}</p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <label className="mb-2 block text-sm font-medium text-slate-300">PDF para verificação</label>
                  <input
                    type="file"
                    accept="application/pdf"
                    onChange={(event) => setVerificationFile(event.target.files?.[0] || null)}
                    className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                  />
                  <button
                    type="button"
                    onClick={handleVerify}
                    className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300"
                  >
                    Verificar assinatura
                  </button>
                </div>
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  {verificationResult ? (
                    <>
                      <p className="text-sm font-medium text-emerald-400">Resultado</p>
                      <p className="mt-3 text-lg font-semibold text-white">{verificationResult.status}</p>
                      <p className="mt-2 text-sm text-slate-400">{verificationResult.detail}</p>
                      <div className="mt-4 rounded-xl border border-gray-800 bg-[#161B22] p-3 text-sm text-slate-300">
                        <p>Hash: {verificationResult.hash}</p>
                        <p className="mt-1">Data: {verificationResult.date}</p>
                      </div>
                    </>
                  ) : (
                    <p className="text-sm text-slate-400">Use o upload para confirmar o estado de uma assinatura no ambiente público.</p>
                  )}
                </div>
              </div>
            </section>
          ) : (
            <section ref={signatureSectionRef} className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
              <div className="rounded-[32px] border border-gray-800 bg-[#0B1218]/90 p-6 shadow-[0_0_40px_rgba(0,0,0,0.24)] backdrop-blur-xl">
              <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Novo documento</p>
                  <h2 className="text-xl font-semibold text-white">Carregar PDF para assinatura</h2>
                </div>
                <div className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
                  Requisito: 20MB
                </div>
              </div>

              <label className="group flex cursor-pointer flex-col items-center justify-center rounded-[32px] border border-dashed border-emerald-400/40 bg-[#0D1118]/80 px-6 py-12 text-center transition hover:border-[#00E676] hover:bg-emerald-500/10 shadow-[inset_0_0_0_1px_rgba(0,230,118,0.06)]">
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full border border-emerald-400/30 bg-[#081913] text-[#00E676]">
                  <svg viewBox="0 0 24 24" className="h-8 w-8" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="M12 16V4m0 0l-4 4m4-4l4 4" strokeLinecap="round" strokeLinejoin="round" />
                    <path d="M5 16v1a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-1" strokeLinecap="round" />
                  </svg>
                </div>
                <p className="text-lg font-semibold text-white">Arraste e solte o PDF</p>
                <p className="mt-2 text-sm text-slate-400">Ou clique para selecionar um arquivo do dispositivo</p>
                <p className="mt-4 text-sm font-semibold text-emerald-400">Tamanho máximo: 20MB</p>
                <input type="file" accept="application/pdf" className="hidden" onChange={handleFileChange} />
              </label>

              {uploadedFile && (
                <div className="mt-4 rounded-xl border border-emerald-400/20 bg-emerald-500/10 p-3 text-sm text-emerald-200">
                  <p className="font-medium">Arquivo pronto</p>
                  <p className="mt-1 text-emerald-100/80">{uploadedFile.name}</p>
                </div>
              )}

              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">Coordenada X</label>
                  <input
                    type="number"
                    value={xCoordinate}
                    onChange={(event) => setXCoordinate(event.target.value)}
                    className="w-full rounded-xl border border-gray-800 bg-[#0D1117] px-4 py-3 text-sm text-white outline-none ring-0 transition focus:border-emerald-400/50"
                    placeholder="120"
                  />
                </div>
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">Coordenada Y</label>
                  <input
                    type="number"
                    value={yCoordinate}
                    onChange={(event) => setYCoordinate(event.target.value)}
                    className="w-full rounded-xl border border-gray-800 bg-[#0D1117] px-4 py-3 text-sm text-white outline-none ring-0 transition focus:border-emerald-400/50"
                    placeholder="80"
                  />
                </div>
              </div>

              <div className="mt-6 rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold text-white">Assinatura visual</p>
                    <p className="text-sm text-slate-400">Desenhe e salve sua assinatura para o documento.</p>
                  </div>
                  <div className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
                    {signatureSaved ? "Salva" : "Pendente"}
                  </div>
                </div>
                <canvas
                  ref={canvasRef}
                  width={520}
                  height={180}
                  onMouseDown={startDrawing}
                  onMouseMove={draw}
                  onMouseUp={stopDrawing}
                  onMouseLeave={stopDrawing}
                  onTouchStart={startDrawing}
                  onTouchMove={draw}
                  onTouchEnd={stopDrawing}
                  className="w-full rounded-xl border border-gray-800 bg-[#161B22]"
                />
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={clearSignature}
                    className="rounded-xl border border-gray-700 bg-[#161B22] px-3 py-2 text-sm text-slate-300"
                  >
                    Limpar
                  </button>
                  <button
                    type="button"
                    onClick={saveSignature}
                    className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-3 py-2 text-sm font-semibold text-emerald-300"
                  >
                    Salvar assinatura
                  </button>
                </div>
                {signaturePreview && (
                  <div className="mt-3 rounded-xl border border-emerald-400/20 bg-emerald-500/10 p-3">
                    <p className="text-sm font-medium text-emerald-200">Pré-visualização salva</p>
                    <img src={signaturePreview} alt="Assinatura salva" className="mt-2 h-14 w-full rounded-lg object-contain" />
                  </div>
                )}
              </div>

              <button
                onClick={handleSign}
                disabled={isSigning}
                className="mt-6 flex w-full items-center justify-center gap-3 rounded-[32px] bg-gradient-to-r from-[#00E676] via-[#31EC90] to-[#22DD6F] px-5 py-5 text-lg font-semibold text-[#04110A] shadow-[0_20px_80px_rgba(0,230,118,0.24)] transition hover:shadow-[0_0_45px_rgba(0,230,118,0.35)] disabled:cursor-not-allowed disabled:opacity-70"
              >
                {isSigning ? (
                  <>
                    <svg className="h-5 w-5 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" className="opacity-25" />
                      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="opacity-80" />
                    </svg>
                    Processando...
                  </>
                ) : (
                  "Assinar Documento"
                )}
              </button>
              <button
                type="button"
                onClick={handleDownloadPdf}
                disabled={!signedPdfUrl}
                className="mt-3 flex w-full items-center justify-center rounded-[32px] border border-emerald-400/20 bg-[#0F181F]/85 px-4 py-3 text-sm font-semibold text-emerald-300 transition hover:bg-[#131E27] disabled:cursor-not-allowed disabled:opacity-60"
              >
                Baixar PDF assinado
              </button>
            </div>

            <div className="rounded-[32px] border border-gray-800 bg-[#0B1218]/90 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)] backdrop-blur-xl">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Auditoria</p>
                  <h2 className="text-xl font-semibold text-white">Assinaturas recentes</h2>
                </div>
              </div>

              <div className="overflow-hidden rounded-xl border border-gray-800">
                <table className="min-w-full divide-y divide-gray-800 text-sm">
                  <thead className="bg-[#0D1117] text-left text-slate-400">
                    <tr>
                      <th className="px-3 py-3 font-medium">Hash</th>
                      <th className="px-3 py-3 font-medium">Data</th>
                      <th className="px-3 py-3 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 bg-[#161B22]">
                    {activity.map((item) => (
                      <tr key={`${item.hash}-${item.date}`} className="text-slate-300">
                        <td className="px-3 py-3 font-mono text-xs text-slate-200">{item.hash}</td>
                        <td className="px-3 py-3">{item.date}</td>
                        <td className="px-3 py-3">
                          <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${item.status === "Assinado" ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-300"}`}>
                            {item.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
          )}
        </main>
      </div>
    </div>
  );
}