import React, { useState, useEffect } from 'react';
import { ArrowLeft, CheckSquare, Square } from 'lucide-react';

// Constantes de Cores
const VALE_GREEN = '#004D40';
const VALE_HEADER_TEXT = '#FFFFFF';
const BACKGROUND_GRAY = '#F0F0F5';
const BUTTON_BLUE = '#303F9F';
const TEXT_COLOR = '#333333';
const ERROR_COLOR = 'red-500';

// --- Funções de Criptografia (Frontend) ---

// Converte ArrayBuffer para string Base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Converte uma string PEM (apenas a parte Base64 da chave pública) para ArrayBuffer
// Usado para importar a chave pública RSA
function pemToArrayBuffer(pem) {
  // Remove o cabeçalho, rodapé e quebras de linha do formato PEM
  const b64Lines = pem.replace('-----BEGIN PUBLIC KEY-----', '')
                      .replace('-----END PUBLIC KEY-----', '')
                      .replace(/\r/g, '') // Remove \r (carriage return)
                      .replace(/\n/g, ''); // Remove \n (newline)
  try {
    const binary_string = window.atob(b64Lines); // Decodifica Base64 para string binária
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.error("Erro ao decodificar PEM para ArrayBuffer (window.atob falhou):", e);
    console.error("PEM problemático (após remoção de header/footer):", b64Lines);
    throw new Error("Formato PEM da chave pública inválido ou corrompido.");
  }
}


// Importa a chave pública RSA (formato PEM SPKI)
async function importRsaPublicKey(pemPublicKey) {
  try {
    const publicKeyBuffer = pemToArrayBuffer(pemPublicKey);
    return await window.crypto.subtle.importKey(
      "spki", // SubjectPublicKeyInfo format (usado por chaves PEM públicas)
      publicKeyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256", // Deve corresponder ao usado no backend para descriptografia (oaepHash)
      },
      true, // whether the key is extractable (não estritamente necessário para apenas criptografar)
      ["encrypt"] // key usages: apenas para criptografar a chave de sessão AES
    );
  } catch (error) {
    console.error("Erro ao importar a chave pública RSA:", error);
    throw error; // Re-lança o erro para ser tratado pelo chamador
  }
}

// Gera uma chave de sessão AES-GCM
async function generateAesSessionKey() {
  try {
    return await window.crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256, // Comprimento da chave em bits (AES-256)
      },
      true, // whether the key is extractable (necessário para exportá-la para criptografia RSA)
      ["encrypt", "decrypt"] // key usages (encrypt para os dados, decrypt não usado aqui mas é comum)
    );
  } catch (error) {
    console.error("Erro ao gerar a chave de sessão AES:", error);
    throw error;
  }
}

// Criptografa dados com RSA-OAEP (usado para a chave de sessão AES)
async function encryptWithRsaPublicKey(rsaPublicKeyObject, dataBuffer) { // dataBuffer é a chave AES exportada como ArrayBuffer
  try {
    return await window.crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
        // Nenhum IV é usado aqui para RSA-OAEP na Web Crypto API
      },
      rsaPublicKeyObject, // O objeto CryptoKey importado
      dataBuffer // A chave AES como ArrayBuffer
    );
  } catch (error) {
    console.error("Erro ao criptografar com RSA-OAEP:", error);
    throw error;
  }
}

// Criptografa dados com AES-GCM (usado para os dados do formulário)
async function encryptWithAesSessionKey(aesKeyObject, dataString) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV de 12 bytes é recomendado para AES-GCM
  const encodedData = new TextEncoder().encode(dataString); // Converte a string de dados para ArrayBuffer
  try {
    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv, // O vetor de inicialização
      },
      aesKeyObject, // O objeto CryptoKey AES
      encodedData // Os dados do formulário como ArrayBuffer
    );
    // Retorna o ciphertext (que já inclui a auth tag no AES-GCM da Web Crypto) e o iv
    return {
      ciphertext: arrayBufferToBase64(ciphertext), // Ciphertext + AuthTag
      iv: arrayBufferToBase64(iv),
    };
  } catch (error) {
    console.error("Erro ao criptografar dados com AES-GCM:", error);
    throw error;
  }
}

// --- Fim das Funções de Criptografia ---


const ValeLogo = () => <div className="text-2xl font-bold" style={{ color: VALE_GREEN }}>VALE</div>;
const Header = () => (
  <header className="w-full p-4 flex items-center justify-between" style={{ backgroundColor: VALE_GREEN, color: VALE_HEADER_TEXT }}>
    <ValeLogo /> <h1 className="text-xl sm:text-2xl font-semibold">VES para Fornecedores</h1> <div className="w-12"></div>
  </header>
);

const validateCPF = (cpf) => { 
  if (!cpf) return "CPF é obrigatório.";
  const cpfClean = cpf.replace(/[^\d]/g, "");
  if (cpfClean.length !== 11) return "CPF deve ter 11 dígitos.";
  if (/^(\d)\1+$/.test(cpfClean)) return "CPF inválido (todos os dígitos iguais).";
  let sum = 0, remainder;
  for (let i = 1; i <= 9; i++) sum += parseInt(cpfClean.substring(i - 1, i)) * (11 - i);
  remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  if (remainder !== parseInt(cpfClean.substring(9, 10))) return "CPF inválido (dígito verificador 1).";
  sum = 0;
  for (let i = 1; i <= 10; i++) sum += parseInt(cpfClean.substring(i - 1, i)) * (12 - i);
  remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  if (remainder !== parseInt(cpfClean.substring(10, 11))) return "CPF inválido (dígito verificador 2).";
  return "";
};
const validateEmail = (email) => {
  if (!email) return "E-mail é obrigatório.";
  if (email.length > 50) return "E-mail deve ter no máximo 50 caracteres.";
  if (/@vale\.com$/i.test(email)) return "Domínio vale.com não é permitido.";
  const emailRegex = /^[a-z0-9.]+@[a-z0-9]+\.[a-z]+(\.[a-z]+)?$/i;
  if (!emailRegex.test(email)) return "Formato de e-mail inválido.";
  return "";
};
const validatePassport = (passport) => {
  if (!passport) return "Passport Number is mandatory.";
  const passportRegex = /^[A-Za-z0-9]{6,20}$/;
  if (!passportRegex.test(passport)) return "Invalid Passport Number format (must be 6-20 alphanumeric characters).";
  return "";
};
const getFormattedDate = () => {
  const today = new Date();
  const month = String(today.getMonth() + 1).padStart(2, '0');
  const day = String(today.getDate()).padStart(2, '0');
  const year = today.getFullYear();
  return `${month}/${day}/${year}`;
};

const InitialScreen = ({ onNavigate }) => {
  const [selectedOption, setSelectedOption] = useState('');
  const handleCheckboxChange = (option) => {
    setSelectedOption(prev => prev === option ? '' : option);
  };
  const nextButtonText = selectedOption === 'BRAZIL' ? "Novo Usuário/Corrige Usuário" : selectedOption === 'OTHER_COUNTRIES' ? "New User/Adjust User" : "";
  return (
    <div className="flex flex-col items-center p-4 sm:p-8" style={{ backgroundColor: BACKGROUND_GRAY, color: TEXT_COLOR }}>
      <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6 w-full max-w-3xl rounded-md shadow-md">
        <p className="font-bold text-sm sm:text-base">PREENCHA SEUS DADOS CORRETAMENTE, PARA QUE NÃO HAJA DIVERGÊNCIAS NO CERTIFICADO!!</p>
        <p className="mt-2 text-xs sm:text-sm">OBS.: O e-mail deverá ser exclusivo e único do usuário, não sendo possível mais de um usuário utilizar o mesmo e-mail. Para usuários que possuem e-mail CO Vale, não cadastrar o CO e sim um e-mail pessoal ou e-mail da empresa de origem. Para usuários estrangeiros utilizar o número do passaporte no campo de CPF.</p>
        <p className="mt-2 text-xs sm:text-sm">Em caso de dúvidas, enviar um email para hse.suppliers@vale.com.</p>
      </div>
      <hr className="w-full max-w-3xl my-4 border-gray-400"/>
      <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6 w-full max-w-3xl rounded-md shadow-md">
        <p className="font-bold text-sm sm:text-base">FILL IN YOUR DATA CORRECTLY, SO THAT THERE ARE NO DIVERGENCES IN THE CERTIFICATE!</p>
        <p className="mt-2 text-xs sm:text-sm">NOTE: The email address must be exclusive and unique to the user. It is not possible for more than one user to use the same email address. For users with a CO email address, do not register the CO email Vale. Register a personal email address or the company of origin's email address. For foreign users , use the passport number in the CPF field.</p>
        <p className="mt-2 text-xs sm:text-sm">If you have any questions, please email hse.suppliers@vale.com</p>
      </div>
      <div className="flex flex-col sm:flex-row justify-center items-center space-y-4 sm:space-y-0 sm:space-x-8 my-6">
        <label className="flex items-center space-x-2 p-3 rounded-md hover:bg-gray-300 cursor-pointer transition-colors">
          <input type="checkbox" className="hidden" checked={selectedOption === 'BRAZIL'} onChange={() => handleCheckboxChange('BRAZIL')} />
          {selectedOption === 'BRAZIL' ? <CheckSquare size={24} color={BUTTON_BLUE} /> : <Square size={24} color={TEXT_COLOR} />}
          <span className="text-lg font-medium">BRASIL</span>
        </label>
        <label className="flex items-center space-x-2 p-3 rounded-md hover:bg-gray-300 cursor-pointer transition-colors">
          <input type="checkbox" className="hidden" checked={selectedOption === 'OTHER_COUNTRIES'} onChange={() => handleCheckboxChange('OTHER_COUNTRIES')} />
          {selectedOption === 'OTHER_COUNTRIES' ? <CheckSquare size={24} color={BUTTON_BLUE} /> : <Square size={24} color={TEXT_COLOR} />}
          <span className="text-lg font-medium">OTHER COUNTRIES</span>
        </label>
      </div>
      {selectedOption && (
        <button onClick={() => onNavigate(selectedOption === 'BRAZIL' ? 'BRAZIL_FORM' : 'INTERNATIONAL_FORM', selectedOption)}
          className="mt-6 px-8 py-3 text-white font-semibold rounded-lg shadow-md hover:opacity-90 transition-opacity"
          style={{ backgroundColor: BUTTON_BLUE }}
        > {nextButtonText} </button>
      )}
    </div>
  );
};

const InputField = ({ label, id, type = "text", value, onChange, error, disabled, placeholder, isOptional = false }) => (
  <div className="flex flex-col w-full">
    <label htmlFor={id} className="mb-1 text-sm font-medium"> {label} {!isOptional && <span className="text-red-500">*</span>} </label>
    <input type={type} id={id} value={value} onChange={onChange} disabled={disabled} placeholder={placeholder}
      className={`p-2 border rounded-md shadow-sm ${disabled ? 'bg-gray-200 cursor-not-allowed' : 'bg-white'} ${error ? 'border-red-500' : 'border-gray-300'} focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors`}
    />
    {error && <p className={`text-xs mt-1 ${ERROR_COLOR}`}>{error}</p>}
  </div>
);

// Componente de Formulário Genérico para evitar repetição
const BaseUserForm = ({ onNavigate, countryOrigin, isBrazilForm }) => {
  const initialFormData = isBrazilForm ? {
    cpf: '', email: '', nome: '', sobrenome: '', numeroContrato: '',
    pais: 'BRAZIL', data: getFormattedDate(),
  } : {
    passportNumber: '', emailAddress: '', firstName: '', lastName: '', contractNumber: '',
    country: 'OTHER COUNTRIES', hiredDate: getFormattedDate(),
  };

  const [formData, setFormData] = useState(initialFormData);
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverRsaPublicKeyObject, setServerRsaPublicKeyObject] = useState(null); // Objeto CryptoKey da chave pública RSA
  const [publicKeyError, setPublicKeyError] = useState('');

  // Busca a chave pública RSA do servidor ao montar o componente
  useEffect(() => {
    const fetchPublicKey = async () => {
      setPublicKeyError(''); // Limpa erro anterior
      try {
        // ATENÇÃO: Atualize esta URL para a URL do seu backend em produção
        const response = await fetch('https://backend-three-blond-77.vercel.app/api/public-key'); // URL do backend
        if (!response.ok) {
          throw new Error(`Falha ao buscar chave pública: ${response.status} ${response.statusText}`);
        }
        const pemPublicKeyString = await response.text();
        if (!pemPublicKeyString.includes('-----BEGIN PUBLIC KEY-----')) {
            console.error("Chave pública recebida do servidor não está no formato PEM esperado:", pemPublicKeyString);
            throw new Error("Formato de chave pública recebido do servidor é inválido.");
        }
        const importedKeyObject = await importRsaPublicKey(pemPublicKeyString);
        setServerRsaPublicKeyObject(importedKeyObject);
        console.log("Chave pública RSA importada com sucesso.");
      } catch (error) {
        console.error("Erro detalhado ao buscar ou importar chave pública RSA:", error);
        setPublicKeyError("Não foi possível carregar a chave de segurança do servidor. Verifique a conexão e o console para detalhes.");
        setServerRsaPublicKeyObject(null);
      }
    };
    fetchPublicKey();
  }, []); // Executa apenas uma vez ao montar

  const handleChange = (e) => {
    const { id, value } = e.target;
    setFormData(prev => ({ ...prev, [id]: value }));
    if (errors[id]) setErrors(prev => ({...prev, [id]: ''}));
  };
  
  useEffect(() => {
    if (isBrazilForm) {
      if (formData.cpf) setErrors(prev => ({ ...prev, cpf: validateCPF(formData.cpf) }));
      else setErrors(prev => ({ ...prev, cpf: '' }));
    } else {
      if (formData.passportNumber) setErrors(prev => ({ ...prev, passportNumber: validatePassport(formData.passportNumber) }));
      else setErrors(prev => ({ ...prev, passportNumber: '' }));
    }
  }, [isBrazilForm, formData.cpf, formData.passportNumber]);

  useEffect(() => {
    const emailToValidate = isBrazilForm ? formData.email : formData.emailAddress;
    if (emailToValidate) setErrors(prev => ({ ...prev, [isBrazilForm ? 'email' : 'emailAddress']: validateEmail(emailToValidate) }));
    else setErrors(prev => ({ ...prev, [isBrazilForm ? 'email' : 'emailAddress']: '' }));
  }, [isBrazilForm, formData.email, formData.emailAddress]);

  const isIdFieldValid = isBrazilForm 
    ? (formData.cpf && !validateCPF(formData.cpf))
    : (formData.passportNumber && !validatePassport(formData.passportNumber));
  
  const isEmailFieldValid = isBrazilForm
    ? (formData.email && !validateEmail(formData.email))
    : (formData.emailAddress && !validateEmail(formData.emailAddress));

  const areDependentFieldsEnabled = isIdFieldValid && isEmailFieldValid;

  const isFormCompletelyValid = areDependentFieldsEnabled &&
    (isBrazilForm ? (formData.nome && formData.sobrenome && formData.numeroContrato)
                  : (formData.firstName && formData.lastName && formData.contractNumber)) &&
    serverRsaPublicKeyObject; // Garante que o objeto CryptoKey da chave pública foi carregado

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!serverRsaPublicKeyObject) {
      alert("Erro: A chave de segurança do servidor não está disponível ou é inválida. Não é possível enviar o formulário.");
      setPublicKeyError("Chave de segurança indisponível. Tente recarregar a página ou contate o suporte.");
      return;
    }
    setIsSubmitting(true);
    setPublicKeyError(''); // Limpa erro de chave pública se o submit iniciar

    let currentErrors = {};
    if (isBrazilForm) {
      if (validateCPF(formData.cpf)) currentErrors.cpf = validateCPF(formData.cpf);
      if (validateEmail(formData.email)) currentErrors.email = validateEmail(formData.email);
      if (!formData.nome) currentErrors.nome = "Nome é obrigatório.";
      if (!formData.sobrenome) currentErrors.sobrenome = "Sobrenome é obrigatório.";
      if (!formData.numeroContrato) currentErrors.numeroContrato = "Número de Contrato é obrigatório.";
    } else { 
      if (validatePassport(formData.passportNumber)) currentErrors.passportNumber = validatePassport(formData.passportNumber);
      if (validateEmail(formData.emailAddress)) currentErrors.emailAddress = validateEmail(formData.emailAddress);
      if (!formData.firstName) currentErrors.firstName = "First Name is required.";
      if (!formData.lastName) currentErrors.lastName = "Last Name is required.";
      if (!formData.contractNumber) currentErrors.contractNumber = "Contract Number is required.";
    }
    setErrors(currentErrors);

    if (Object.keys(currentErrors).length === 0) {
      const dataToSubmitObject = { 
        'User ID': isBrazilForm ? formData.cpf : formData.passportNumber,
        'Active (*required)': 'YES', 'First Name': isBrazilForm ? formData.nome : formData.firstName,
        'Last Name': isBrazilForm ? formData.sobrenome : formData.lastName, 'Middle Initial': '', 'Gender': '', 'Job Code ID': '', 'Job Title': '',
        'Role (*required)': 'USER_CONTRACTOR', 'Job Location ID': '', 'Domain ID (*required)': 'VES_FOR_CONTRACTORS', 'Organization ID': '',
        'Employee Type ID': '', 'Employee Status ID': '', 'Address': '', 'City': '', 'State/Province': '', 'Postal Code': '',
        'Country': isBrazilForm ? formData.pais : '', 'Region ID': '',
        'Email Address': isBrazilForm ? formData.email : formData.emailAddress,
        'Hired Date': isBrazilForm ? formData.data : formData.hiredDate, 'Terminated Date': '', 'Supervisor ID': '', 'Coach': '', 'Resume': '', 'Comments': '', 'Account Code ID': '',
        'User May Use Organization Account Code': '', 'Phone Number I': '', 'Phone Number Description I': '',
        'Phone Number 2': '', 'Phone Number Description 2': '', 'Phone Number 3': '', 'Phone Number Description 3': '',
        'Time Zone': 'America/Sao_Paulo', 'Locale': 'Brazilian Portuguese', 'Currency ID': 'BRL',
        'Prior Years of Service (Years)': '', 'Prior Years of Service (Months)': '', 'Related Instructor ID': '',
        'Custom Column Name N1': 'Manager', 'Custom Column Value V1': 'GER GLOBAL SSMA FORNECEDORES - PATRICIA VELOSO DE ALMEIDA',
        'Custom Column Name N2': 'Centro de Custo', 'Custom Column Value V2': '1010132',
        'Custom Column Name N3': '', 'Custom Column Value V3': isBrazilForm ? formData.numeroContrato : formData.contractNumber,
        'Custom Column Name N4': '', 'Custom Column Value V4': '', 'Custom Column Name N5': '', 'Custom Column Value V5': '',
        'Custom Column Name N6': '', 'Custom Column Value V6': '', 'Custom Column Name N7': '', 'Custom Column Value V7': '',
        'Custom Column Name N8': '', 'Custom Column Value V8': '', 'Custom Column Name N9': '', 'Custom Column Value V9': '',
        'Custom Column Name N10': '', 'Custom Column Value V10': '', 'Include in government reporting': '',
        '2483 Legal Entity': '', '2483 Employee Class': '', 'Hourly Rate': '', 'Hourly Rate Currency': '',
        'Native DeepLink User': '', 'Adjusted Hourly Rate': '', 'Adjusted Hourly Rate Currency': '', 'Date of Birth': '',
        'Disability Classification ID': '', 'Gamification User ID': '', 'License User Type': 'FUNCTIONAL',
        'Login Site': '', 'Shopping Account Type': 'EXTERNAL',
      };
      const formDataString = JSON.stringify(dataToSubmitObject);

      try {
        console.log("Iniciando processo de criptografia e envio...");
        // 1. Gerar chave de sessão AES
        const aesSessionKeyObject = await generateAesSessionKey(); 
        console.log("Chave de sessão AES gerada.");
        
        // 2. Exportar chave AES para formato raw (ArrayBuffer) para ser criptografada com RSA
        const exportedAesKeyRawBuffer = await window.crypto.subtle.exportKey("raw", aesSessionKeyObject);
        console.log("Chave de sessão AES exportada para raw buffer.");

        // 3. Criptografar a chave AES (raw ArrayBuffer) com a chave pública RSA do servidor
        console.log("Criptografando chave de sessão AES com RSA Public Key Object:", serverRsaPublicKeyObject);
        const encryptedSessionKeyBuffer = await encryptWithRsaPublicKey(serverRsaPublicKeyObject, exportedAesKeyRawBuffer);
        const encryptedSessionKeyBase64 = arrayBufferToBase64(encryptedSessionKeyBuffer);
        console.log("Chave de sessão AES criptografada com RSA:", encryptedSessionKeyBase64.substring(0,30) + "...");

        // 4. Criptografar os dados do formulário com a chave de sessão AES original (CryptoKey)
        const { ciphertext: encryptedFormDataBase64, iv: ivBase64 } = await encryptWithAesSessionKey(aesSessionKeyObject, formDataString);
        console.log("Dados do formulário criptografados com AES:", encryptedFormDataBase64.substring(0,30) + "...");
        
        const payload = {
          encryptedSessionKey: encryptedSessionKeyBase64, 
          iv: ivBase64, 
          encryptedData: encryptedFormDataBase64, 
        };
        
        console.log("Payload final a ser enviado:", JSON.stringify(payload, null, 2).substring(0, 200) + "...");
        // ATENÇÃO: Atualize esta URL para a URL do seu backend em produção
        const response = await fetch('https://backend-three-blond-77.vercel.app/api/submit-form', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const result = await response.json();

        if (response.ok) {
          alert(`Sucesso (criptografia híbrida): ${result.message}`); 
          onNavigate('INITIAL'); 
        } else {
          console.error("Erro do backend:", result);
          alert(`Erro ao enviar: ${result.message || 'Ocorreu um problema no servidor.'}`);
        }
      } catch (error) {
        console.error("Erro na criptografia ou requisição fetch:", error);
        alert(`Erro de criptografia ou conexão: ${error.message}. Não foi possível enviar os dados.`);
      } finally {
        setIsSubmitting(false);
      }
    } else {
        setIsSubmitting(false);
    }
  };
  
  const idFieldLabel = isBrazilForm ? "CPF" : "Passport Number";
  const idFieldId = isBrazilForm ? "cpf" : "passportNumber";
  const idFieldValue = isBrazilForm ? formData.cpf : formData.passportNumber;
  const idFieldError = isBrazilForm ? errors.cpf : errors.passportNumber;
  const idFieldPlaceholder = isBrazilForm ? "___________" : "Your passport number";
  const emailFieldLabel = isBrazilForm ? "Email" : "Email Address";
  const emailFieldId = isBrazilForm ? "email" : "emailAddress";
  const emailFieldValue = isBrazilForm ? formData.email : formData.emailAddress;
  const emailFieldError = isBrazilForm ? errors.email : errors.emailAddress;
  const nameFieldLabel = isBrazilForm ? "Primeiro Nome" : "First Name";
  const nameFieldId = isBrazilForm ? "nome" : "firstName";
  const nameFieldValue = isBrazilForm ? formData.nome : formData.firstName;
  const nameFieldError = isBrazilForm ? errors.nome : errors.firstName;
  const nameFieldPlaceholder = isBrazilForm ? "Seu primeiro nome" : "Your first name";
  const lastNameFieldLabel = isBrazilForm ? "Sobrenome" : "Last Name";
  const lastNameFieldId = isBrazilForm ? "sobrenome" : "lastName";
  const lastNameFieldValue = isBrazilForm ? formData.sobrenome : formData.lastName;
  const lastNameFieldError = isBrazilForm ? errors.sobrenome : errors.lastName;
  const lastNameFieldPlaceholder = isBrazilForm ? "Seu sobrenome" : "Your last name";
  const contractFieldLabel = isBrazilForm ? "Número de Contrato" : "Contract Number";
  const contractFieldId = isBrazilForm ? "numeroContrato" : "contractNumber";
  const contractFieldValue = isBrazilForm ? formData.numeroContrato : formData.contractNumber;
  const contractFieldError = isBrazilForm ? errors.numeroContrato : errors.contractNumber;
  const contractFieldPlaceholder = isBrazilForm ? "Seu número de contrato" : "Your contract number";
  const dateFieldLabel = isBrazilForm ? "Data" : "Hired Date";
  const dateFieldId = isBrazilForm ? "data" : "hiredDate";
  const dateFieldValue = isBrazilForm ? formData.data : formData.hiredDate;
  const countryFieldId = isBrazilForm ? "pais" : "country";
  const countryFieldValue = isBrazilForm ? formData.pais : formData.country;

  return (
    <div className="p-4 sm:p-8" style={{ backgroundColor: BACKGROUND_GRAY }}>
      <form onSubmit={handleSubmit} className="max-w-4xl mx-auto bg-white p-6 sm:p-8 rounded-lg shadow-xl">
        <h2 className="text-2xl font-semibold mb-6 text-center" style={{color: VALE_GREEN}}>
          {isBrazilForm ? "Cadastro de Usuário - Brasil" : "User Registration - International"}
        </h2>
        {publicKeyError && <p className={`text-center font-semibold mb-4 ${ERROR_COLOR}`}>{publicKeyError}</p>}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <InputField label={dateFieldLabel} id={dateFieldId} value={dateFieldValue} disabled={true} />
          <InputField label={idFieldLabel} id={idFieldId} value={idFieldValue} onChange={handleChange} error={idFieldError} placeholder={idFieldPlaceholder}/>
          <InputField label={emailFieldLabel} id={emailFieldId} type="email" value={emailFieldValue} onChange={handleChange} error={emailFieldError} disabled={!isIdFieldValid} placeholder="seuemail@dominio.com"/>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <InputField label={nameFieldLabel} id={nameFieldId} value={nameFieldValue} onChange={handleChange} error={nameFieldError} disabled={!areDependentFieldsEnabled} placeholder={nameFieldPlaceholder}/>
          <InputField label={lastNameFieldLabel} id={lastNameFieldId} value={lastNameFieldValue} onChange={handleChange} error={lastNameFieldError} disabled={!areDependentFieldsEnabled} placeholder={lastNameFieldPlaceholder}/>
          <InputField label={contractFieldLabel} id={contractFieldId} value={contractFieldValue} onChange={handleChange} error={contractFieldError} disabled={!areDependentFieldsEnabled} placeholder={contractFieldPlaceholder}/>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
           <InputField label={isBrazilForm ? "País" : "Country"} id={countryFieldId} value={countryFieldValue} disabled={true} />
           <div></div> <div></div>
        </div>
        <div className="flex flex-col sm:flex-row justify-between items-center mt-8">
          <button type="submit" disabled={!isFormCompletelyValid || isSubmitting || !!publicKeyError}
            className="px-6 py-3 text-white font-semibold rounded-lg shadow-md hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed w-full sm:w-auto mb-4 sm:mb-0"
            style={{ backgroundColor: BUTTON_BLUE }}
          > {isSubmitting ? (isBrazilForm ? 'Enviando...' : 'Submitting...') : (isBrazilForm ? 'Enviar' : 'Submit')} </button>
          <button type="button" onClick={() => onNavigate('INITIAL')}
            className="flex items-center justify-center px-6 py-3 text-gray-700 font-semibold rounded-lg shadow-md hover:bg-gray-200 transition-colors border border-gray-300 w-full sm:w-auto"
          > <ArrowLeft size={20} className="mr-2"/> {isBrazilForm ? 'Voltar' : 'Back'} </button>
        </div>
      </form>
    </div>
  );
};

const BrazilForm = (props) => <BaseUserForm {...props} isBrazilForm={true} />;
const InternationalForm = (props) => <BaseUserForm {...props} isBrazilForm={false} />;

export default function App() {
  const [currentPage, setCurrentPage] = useState('INITIAL'); 
  const [countryOrigin, setCountryOrigin] = useState(''); 

  const handleNavigation = (page, origin = '') => {
    setCurrentPage(page);
    if (origin) setCountryOrigin(origin);
  };

  useEffect(() => {
    if (!document.querySelector('script[src="https://cdn.tailwindcss.com"]')) {
        const tailwindScript = document.createElement('script');
        tailwindScript.src = 'https://cdn.tailwindcss.com';
        document.head.appendChild(tailwindScript);
    }
    if (!document.querySelector('link[href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"]')) {
        const fontScript = document.createElement('link');
        fontScript.href = 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap';
        fontScript.rel = 'stylesheet';
        document.head.appendChild(fontScript);
    }
  }, []);

  return (
    <div className="min-h-screen flex flex-col" style={{ fontFamily: 'Inter, sans-serif' }}>
      <Header />
      <main className="flex-grow" style={{ backgroundColor: BACKGROUND_GRAY }}>
        {currentPage === 'INITIAL' && <InitialScreen onNavigate={handleNavigation} />}
        {currentPage === 'BRAZIL_FORM' && <BrazilForm onNavigate={handleNavigation} countryOrigin={countryOrigin} />}
        {currentPage === 'INTERNATIONAL_FORM' && <InternationalForm onNavigate={handleNavigation} countryOrigin={countryOrigin} />}
      </main>
      <footer className="p-4 text-center text-sm text-gray-600" style={{backgroundColor: BACKGROUND_GRAY}}>
        © {new Date().getFullYear()} Vale S.A. - User Registration System
      </footer>
    </div>
  );
}
