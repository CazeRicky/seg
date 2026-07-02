import React, { useEffect, useRef, useState } from "react";

const initialActivity = [
  { hash: "0x8A1F...2C9D", date: "01/07/2026 14:32", status: "Assinado", detail: "Contrato de parceria" },
  { hash: "0x4B7E...91FA", date: "30/06/2026 09:15", status: "Assinado", detail: "Termo de confidencialidade" },
  { hash: "0x22C3...7D11", date: "29/06/2026 18:48", status: "Pendente", detail: "Proposta comercial" },
];

const navItems = ["Dashboard", "Security & 2FA", "Public Verification"];
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;
const API_BASE = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000/api/v1";

export default function MainDashboard() {
  const canvasRef = useRef(null);
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
  const [statusMessage, setStatusMessage] = useState("Pronto para validar sua próxima assinatura.");
  const [authError, setAuthError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [isDrawing, setIsDrawing] = useState(false);
  const [signatureSaved, setSignatureSaved] = useState(false);
  const [signaturePreview, setSignaturePreview] = useState(null);
  const [verificationHash, setVerificationHash] = useState("");
  const [verificationResult, setVerificationResult] = useState(null);
  const [accessToken, setAccessToken] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [qrCodeImage, setQrCodeImage] = useState(null);
  const [qrCodeSecret, setQrCodeSecret] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [signedPdfUrl, setSignedPdfUrl] = useState(null);
  const [signedPdfName, setSignedPdfName] = useState("");

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
    setStatusMessage("�rea de assinatura limpa.");
  };

  const saveSignature = () => {
    const dataUrl = canvasRef.current.toDataURL("image/png");
    setSignaturePreview(dataUrl);
    setSignatureSaved(true);
    setStatusMessage("Assinatura salva e vinculada ao documento.");
  };

  const apiFetch = async (path, options = {}) => {
    const defaultHeaders = { "Content-Type": "application/json" };
    const authHeaders = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
    const headers = { ...defaultHeaders, ...authHeaders, ...(options.headers || {}) };
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

    if (!response.ok) {
      throw body || new Error(response.statusText);
    }

    return body;
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
      setCurrentUser({ username: email.trim().toLowerCase(), email: email.trim().toLowerCase() });
      setIsAuthenticated(true);
      setTwoFactorRequired(false);
      setTotpCode("");
      setSuccessMessage("Login concluído com sucesso.");
      setStatusMessage(`Bem-vindo, ${email.trim().toLowerCase()}.`);
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

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];
    if (file) {
      setUploadedFile(file);
      setSignedPdfUrl(null);
      setSignedPdfName("");
      setStatusMessage(`Arquivo selecionado: ${file.name}`);
      setActivity((current) => [
        { hash: "0xNEW...1A2B", date: new Date().toLocaleString("pt-BR"), status: "Em análise", detail: file.name },
        ...current.slice(0, 2),
      ]);
    }
  };

  const createSignedPdf = async (file, signerName, hash, signatureDataUrl) => {
    const safeName = (file?.name || "documento.pdf").replace(/[^a-zA-Z0-9.-]+/g, "_");
    const pdfBytes = await file.arrayBuffer();

    const module = await import("https://cdn.jsdelivr.net/npm/pdf-lib/dist/pdf-lib.esm.min.js");
    const { PDFDocument, StandardFonts, rgb } = module;
    const pdfDoc = await PDFDocument.load(pdfBytes);
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const { width, height } = firstPage.getSize();
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

    const footerHeight = 140;
    const boxX = 40;
    const boxY = 40;
    const boxWidth = width - boxX * 2;
    const boxHeight = footerHeight;

    firstPage.drawRectangle({
      x: boxX,
      y: boxY,
      width: boxWidth,
      height: boxHeight,
      color: rgb(1, 1, 1),
      borderColor: rgb(0, 0.8, 0.24),
      borderWidth: 1,
    });

    firstPage.drawText(`Assinante: ${signerName}`, {
      x: boxX + 12,
      y: boxY + boxHeight - 26,
      size: 11,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });
    firstPage.drawText(`Hash: ${hash}`, {
      x: boxX + 12,
      y: boxY + boxHeight - 44,
      size: 10,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });
    firstPage.drawText(`Data: ${new Date().toLocaleString("pt-BR")}`, {
      x: boxX + 12,
      y: boxY + boxHeight - 62,
      size: 10,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });
    firstPage.drawText("Documento assinado digitalmente", {
      x: boxX + 12,
      y: boxY + boxHeight - 84,
      size: 12,
      font: fontBold,
      color: rgb(0, 0.5, 0),
    });

    if (signatureDataUrl) {
      try {
        const signatureImage = await pdfDoc.embedPng(signatureDataUrl);
        const sigWidth = 170;
        const sigHeight = (signatureImage.height / signatureImage.width) * sigWidth;
        firstPage.drawImage(signatureImage, {
          x: width - sigWidth - 40,
          y: boxY + 12,
          width: sigWidth,
          height: sigHeight,
        });
      } catch (error) {
        console.warn("Não foi possível embutir a assinatura como imagem:", error);
      }
    }

    firstPage.drawText("ASSINADO", {
      x: width - 160,
      y: boxY + boxHeight - 28,
      size: 16,
      font: fontBold,
      color: rgb(0.05, 0.5, 0.15),
    });

    const signaturePage = pdfDoc.addPage([width, height]);
    signaturePage.drawText("Detalhes da assinatura", {
      x: 40,
      y: height - 60,
      size: 18,
      font: fontBold,
      color: rgb(0, 0.2, 0.4),
    });
    signaturePage.drawText(`Documento original: ${safeName}`, {
      x: 40,
      y: height - 90,
      size: 12,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });
    signaturePage.drawText(`Assinante: ${signerName}`, {
      x: 40,
      y: height - 110,
      size: 12,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });
    signaturePage.drawText(`Hash: ${hash}`, {
      x: 40,
      y: height - 130,
      size: 12,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });
    signaturePage.drawText(`Data: ${new Date().toLocaleString("pt-BR")}`, {
      x: 40,
      y: height - 150,
      size: 12,
      font,
      color: rgb(0.07, 0.11, 0.18),
    });

    const pdfBytesSigned = await pdfDoc.save();
    return new Blob([pdfBytesSigned], { type: "application/pdf" });
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
    setStatusMessage("Aplicando assinatura criptográfica e registro auditável...");

    try {
      const signedHash = `0x${Math.random().toString(16).slice(2, 8).toUpperCase()}...`;
      const signedPdfBlob = await createSignedPdf(uploadedFile, currentUser?.username || "Usuário", signedHash, signaturePreview);
      const signedPdfUrlValue = window.URL.createObjectURL(signedPdfBlob);
      setSignedPdfUrl(signedPdfUrlValue);
      setSignedPdfName(`assinado-${(uploadedFile.name || "documento.pdf").replace(/\.pdf$/i, "")}.pdf`);
      setSignatureCount((count) => count + 1);
      setActivity((current) => [
        {
          hash: signedHash,
          date: new Date().toLocaleString("pt-BR"),
          status: "Assinado",
          detail: uploadedFile?.name || "Documento PDF",
        },
        ...current.slice(0, 2),
      ]);
      setStatusMessage("Documento assinado com sucesso. PDF pronto para download.");
    } catch (error) {
      setStatusMessage("Falha ao assinar o documento. Tente novamente.");
      console.error(error);
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
    const nextCode = String(100000 + Math.floor(Math.random() * 900000)).padStart(6, "0");
    if (currentUser) {
      const updatedUser = { ...currentUser, totpCode: nextCode };
      setCurrentUser(updatedUser);
      setRegisteredUsers((users) => users.map((user) => (user.id === updatedUser.id ? updatedUser : user)));
      setStatusMessage(`Novo código 2FA gerado para ${updatedUser.name}.`);
      return;
    }
    setStatusMessage("Faça login para regenerar o código 2FA.");
  };

  const handleVerify = () => {
    const normalizedHash = verificationHash.trim().toUpperCase();
    if (!normalizedHash) {
      setVerificationResult(null);
      setStatusMessage("Informe um hash para validar a assinatura.");
      return;
    }

    const match = activity.find((entry) => entry.hash.toUpperCase().includes(normalizedHash));
    if (match) {
      setVerificationResult({
        hash: normalizedHash,
        status: match.status,
        detail: match.detail,
        date: match.date,
        verified: true,
      });
      setStatusMessage(`Verificação concluída para ${normalizedHash}.`);
      return;
    }

    setVerificationResult({
      hash: normalizedHash,
      status: "Não verificado",
      detail: "Nenhum registro encontrado para esse hash.",
      date: "-",
      verified: false,
    });
    setStatusMessage("Nenhum registro encontrado para o hash informado.");
  };
  const handleLogout = () => {
    setIsAuthenticated(false);
    setCurrentUser(null);
    setPendingUser(null);
    setTwoFactorRequired(false);
    setActiveNav("Dashboard");
    resetAuthForm();
    setStatusMessage("Sess�o encerrada. Fa�a login para continuar.");
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
              Assine documentos com rastreabilidade, confian�a e auditoria completa.
            </h2>
            <p className="mt-4 max-w-xl text-base text-slate-400">
              Crie uma conta ou entre com suas credenciais para acessar a �rea protegida.
            </p>
            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              {[
                { label: "Criptografia", value: "256-bit" },
                { label: "Hash", value: "Audit�vel" },
                { label: "Tempo", value: "< 2s" },
              ].map((item) => (
                <div key={item.label} className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <p className="text-xs uppercase tracking-[0.25em] text-slate-500">{item.label}</p>
                  <p className="mt-2 text-lg font-semibold text-[#00E676]">{item.value}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="w-full border-t border-gray-800 bg-[#0D1117]/80 p-8 sm:p-10 lg:w-[430px] lg:border-l lg:border-t-0">
            <form onSubmit={handleAuthSubmit} className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">{authMode === "login" ? "Login" : "Cadastro"}</p>
                  <h3 className="mt-1 text-2xl font-semibold text-white">{authMode === "login" ? "Bem-vindo de volta" : "Criar conta"}</h3>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setAuthMode(authMode === "login" ? "register" : "login");
                    setAuthError("");
                    setSuccessMessage("");
                    resetAuthForm();
                  }}
                  className="text-sm font-semibold text-emerald-400"
                >
                  {authMode === "login" ? "Criar conta" : "Entrar"}
                </button>
              </div>

              {authMode === "register" && (
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">Nome</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
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
                  className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
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
                  className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
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
                    className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                    placeholder="Repita a senha"
                    required
                  />
                </div>
              )}

              {twoFactorRequired && (
                <div>
                  <label className="mb-2 block text-sm font-medium text-slate-300">C�digo TOTP</label>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.target.value)}
                    className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                    placeholder="123456"
                    required
                  />
                </div>
              )}

              {authError && <p className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">{authError}</p>}
              {successMessage && <p className="rounded-xl border border-emerald-400/20 bg-emerald-500/10 p-3 text-sm text-emerald-200">{successMessage}</p>}

              <button
                type="submit"
                disabled={isLoading}
                className="flex w-full items-center justify-center gap-2 rounded-2xl border border-emerald-400/30 bg-[#00E676] px-4 py-3 text-sm font-semibold text-[#04110A] transition hover:shadow-[0_0_25px_rgba(0,230,118,0.3)] disabled:cursor-not-allowed disabled:opacity-80"
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
        <aside className="w-full border-b border-gray-800 bg-[#0D1117]/80 px-4 py-6 backdrop-blur-xl lg:w-72 lg:border-b-0 lg:border-r lg:px-6">
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
                      ? "border border-emerald-400/30 bg-emerald-500/10 text-[#00E676] shadow-[0_0_20px_rgba(0,230,118,0.15)]"
                      : "border border-transparent bg-transparent text-slate-300 hover:border-gray-700 hover:bg-[#161B22]"
                  }`}
                >
                  <span>{item}</span>
                  <span className="text-xs text-slate-500">0{index + 1}</span>
                </button>
              );
            })}
          </nav>

          <div className="mt-8 rounded-xl border border-gray-800 bg-[#161B22]/80 p-4 shadow-[0_0_30px_rgba(0,0,0,0.25)]">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Status do sistema</p>
            <div className="mt-3 flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#00E676] shadow-[0_0_8px_#00E676]" />
              <span className="text-sm text-slate-200">Opera��o segura online</span>
            </div>
            <p className="mt-3 text-sm text-slate-400">Assinaturas criptogr�ficas protegidas por certificados v�lidos.</p>
          </div>
        </aside>

        <main className="flex-1 p-4 sm:p-6 lg:p-8">
          <header className="mb-6 flex flex-col gap-4 rounded-2xl border border-gray-800 bg-[#161B22]/70 p-4 shadow-[0_0_30px_rgba(0,0,0,0.2)] backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-medium text-emerald-400">Dashboard principal</p>
              <h1 className="text-2xl font-semibold text-white">Assinatura digital de documentos</h1>
              <p className="mt-1 text-sm text-slate-400">{statusMessage}</p>
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
              { label: "Se��o ativa", value: activeNav },
            ].map((item) => (
              <div key={item.label} className="rounded-2xl border border-gray-800 bg-[#161B22]/80 p-4 shadow-[0_0_25px_rgba(0,0,0,0.18)]">
                <p className="text-sm text-slate-400">{item.label}</p>
                <p className="mt-2 text-2xl font-semibold text-white">{item.value}</p>
              </div>
            ))}
          </section>

          {activeNav === "Security & 2FA" && (
            <section className="mb-6 rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)]">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Seguran�a</p>
                  <h2 className="text-xl font-semibold text-white">Autentica��o de dois fatores</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    O fluxo agora exige um c�digo TOTP ap�s a senha, simulando o requisito de seguran�a do projeto.
                  </p>
                </div>
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                  <p className="font-semibold">C�digo 2FA ativo</p>
                  <p className="mt-1 text-emerald-100/80">{currentUser?.totpCode || "123456"}</p>
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
                  <p className="font-semibold">Código 2FA ativo</p>
                  <p className="mt-1 text-emerald-100/80">{currentUser?.totpCode || "123456"}</p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <h3 className="text-lg font-semibold text-white">Status da autenticação</h3>
                  <ul className="mt-4 space-y-3 text-sm text-slate-400">
                    <li>• Login protegido por senha e verificação adicional.</li>
                    <li>• O código TOTP é exibido para a sessão atual.</li>
                    <li>• Você pode regenerar o código para simular uma rotação segura.</li>
                  </ul>
                </div>
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <h3 className="text-lg font-semibold text-white">Ações rápidas</h3>
                  <button
                    type="button"
                    onClick={handleRegenerate2FA}
                    className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300"
                  >
                    Regenerar código 2FA
                  </button>
                  <p className="mt-3 text-sm text-slate-400">
                    O campo de autenticação agora acompanha a mudança do código do usuário logado.
                  </p>
                </div>
              </div>
            </section>
          ) : activeNav === "Public Verification" ? (
            <section className="mb-6 rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)]">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Verificação pública</p>
                  <h2 className="text-xl font-semibold text-white">Validar assinatura digital</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    Informe um hash ou identificador para consultar o estado da assinatura no ledger simulado.
                  </p>
                </div>
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                  <p className="font-semibold">Status da consulta</p>
                  <p className="mt-1 text-emerald-100/80">{verificationResult?.verified ? "Validado" : "Aguardando"}</p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-2xl border border-gray-800 bg-[#0D1117]/70 p-4">
                  <label className="mb-2 block text-sm font-medium text-slate-300">Hash / identificador</label>
                  <input
                    type="text"
                    value={verificationHash}
                    onChange={(event) => setVerificationHash(event.target.value)}
                    className="w-full rounded-xl border border-gray-800 bg-[#161B22] px-4 py-3 text-sm text-white outline-none transition focus:border-emerald-400/50"
                    placeholder="0x8A1F..."
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
                    <p className="text-sm text-slate-400">Use a busca para confirmar o estado de uma assinatura no ambiente público.</p>
                  )}
                </div>
              </div>
            </section>
          ) : (
            <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
              <div className="rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)] backdrop-blur-xl">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-emerald-400">Novo documento</p>
                  <h2 className="text-xl font-semibold text-white">Carregar PDF para assinatura</h2>
                </div>
                <div className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
                  Requisito: 20MB
                </div>
              </div>

              <label className="group flex cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed border-emerald-400/30 bg-[#0D1117]/80 px-6 py-10 text-center transition hover:border-[#00E676] hover:bg-emerald-500/5">
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full border border-emerald-400/30 bg-emerald-500/10 text-[#00E676]">
                  <svg viewBox="0 0 24 24" className="h-8 w-8" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="M12 16V4m0 0l-4 4m4-4l4 4" strokeLinecap="round" strokeLinejoin="round" />
                    <path d="M5 16v1a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-1" strokeLinecap="round" />
                  </svg>
                </div>
                <p className="text-lg font-semibold text-white">Arraste e solte o PDF</p>
                <p className="mt-2 text-sm text-slate-400">Ou clique para selecionar um arquivo do dispositivo</p>
                <p className="mt-3 text-sm font-medium text-emerald-400">Tamanho m�ximo: 20MB</p>
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
                    <p className="text-sm font-medium text-emerald-200">Pr�-visualiza��o salva</p>
                    <img src={signaturePreview} alt="Assinatura salva" className="mt-2 h-14 w-full rounded-lg object-contain" />
                  </div>
                )}
              </div>

              <button
                onClick={handleSign}
                disabled={isSigning}
                className="mt-6 flex w-full items-center justify-center gap-3 rounded-2xl border border-emerald-400/30 bg-[#00E676] px-5 py-4 text-lg font-semibold text-[#04110A] transition hover:shadow-[0_0_30px_rgba(0,230,118,0.35)] disabled:cursor-not-allowed disabled:opacity-80"
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
                className="mt-3 flex w-full items-center justify-center rounded-2xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-3 text-sm font-semibold text-emerald-300 transition disabled:cursor-not-allowed disabled:opacity-60"
              >
                Baixar PDF assinado
              </button>
            </div>

            <div className="rounded-2xl border border-gray-800 bg-[#161B22]/80 p-5 shadow-[0_0_35px_rgba(0,0,0,0.2)] backdrop-blur-xl">
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