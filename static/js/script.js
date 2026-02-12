/* ========================================
   JavaScript - Interatividade e Lógica
   ======================================== */

// Variável global para armazenar o serviço selecionado
let servicoAtual = '';

/**
 * Função para mostrar um alerta
 */
function mostrarAlerta() {
    alert('👋 Bem-vindo! Obrigado por clicar.');
}

/**
 * Função para selecionar um serviço
 * @param {string} servico - Nome do serviço selecionado
 */
function selecionarServico(servico) {
    servicoAtual = servico;
    const modal = document.getElementById('servicoSelecionado');
    modal.textContent = `Serviço selecionado: ${servico}`;
    
    console.log(`Serviço clicado: ${servico}`);
    
    // Mostrar animação de feedback
    animarBotao(event.target);
}

/**
 * Animar botão quando clicado
 * @param {HTMLElement} elemento - Elemento do botão
 */
function animarBotao(elemento) {
    elemento.style.transform = 'scale(0.95)';
    setTimeout(() => {
        elemento.style.transform = 'scale(1)';
    }, 200);
}

/**
 * Enviar formulário com validação
 * @param {Event} event - Evento do formulário
 */
function enviarFormulario(event) {
    event.preventDefault();
    
    // Obter valores do formulário
    const nome = document.getElementById('nome').value.trim();
    const email = document.getElementById('email').value.trim();
    const mensagem = document.getElementById('mensagem').value.trim();
    
    // Validar campos
    if (!nome || !email || !mensagem) {
        mostrarNotificacao('Por favor, preencha todos os campos!', 'warning');
        return;
    }
    
    // Validar email
    if (!validarEmail(email)) {
        mostrarNotificacao('Por favor, insira um email válido!', 'danger');
        return;
    }
    
    // Simular envio (em produção, enviar para servidor)
    console.log('Dados do formulário:', { nome, email, mensagem });
    
    mostrarNotificacao('✅ Mensagem enviada com sucesso!', 'success');
    
    // Limpar formulário
    document.getElementById('formulario').reset();
    
    // Simular envio para servidor (exemplo)
    // enviarParaServidor({ nome, email, mensagem });
}

/**
 * Validar formato de email
 * @param {string} email - Email a validar
 * @returns {boolean} - Email válido ou não
 */
function validarEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

/**
 * Mostrar notificação toast
 * @param {string} mensagem - Mensagem a exibir
 * @param {string} tipo - Tipo de notificação (success, warning, danger, info)
 */
function mostrarNotificacao(mensagem, tipo = 'info') {
    // Criar elemento toast
    const toast = document.createElement('div');
    toast.className = `alert alert-${tipo} alert-dismissible fade show`;
    toast.setAttribute('role', 'alert');
    toast.style.position = 'fixed';
    toast.style.top = '20px';
    toast.style.right = '20px';
    toast.style.zIndex = '9999';
    toast.style.minWidth = '300px';
    toast.style.animation = 'slideIn 0.5s ease-out';
    
    toast.innerHTML = `
        ${mensagem}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(toast);
    
    // Remover notificação após 5 segundos
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

/**
 * Função para enviar dados ao servidor
 * @param {object} dados - Dados a enviar
 */
async function enviarParaServidor(dados) {
    try {
        const response = await fetch('/api/contato', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(dados)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const resultado = await response.json();
        console.log('Resposta do servidor:', resultado);
        mostrarNotificacao('Mensagem enviada com sucesso!', 'success');
    } catch (error) {
        console.error('Erro ao enviar:', error);
        mostrarNotificacao('Erro ao enviar mensagem. Tente novamente.', 'danger');
    }
}

/**
 * Smooth scroll para âncoras
 */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

/**
 * Destacar link ativo na navbar ao scroll
 */
window.addEventListener('scroll', () => {
    let current = '';
    
    document.querySelectorAll('section').forEach(section => {
        const sectionTop = section.offsetTop;
        if (pageYOffset >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href').slice(1) === current) {
            link.classList.add('active');
        }
    });
});

/**
 * Efeito de digitação (typing effect)
 * @param {string} elemento - Seletor CSS do elemento
 * @param {string} texto - Texto a digitar
 * @param {number} velocidade - Velocidade em ms
 */
function efeitoDigitacao(elemento, texto, velocidade = 100) {
    const el = document.querySelector(elemento);
    if (!el) return;
    
    let i = 0;
    el.textContent = '';
    
    function digitar() {
        if (i < texto.length) {
            el.textContent += texto.charAt(i);
            i++;
            setTimeout(digitar, velocidade);
        }
    }
    
    digitar();
}

/**
 * Inicializar aplicação
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 Aplicação iniciada!');
    
    // Adicionar listeners de eventos
    const botoesSaibaMais = document.querySelectorAll('.btn-primary');
    botoesSaibaMais.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transition = 'all 0.3s ease';
        });
    });
    
    // Exemplo: Adicionar estilos dinâmicos
    console.log('✅ Inicialização concluída');
});

/**
 * Adicionar animação CSS dinamicamente
 */
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);
