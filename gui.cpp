#include <wx/wxprec.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif
#include <wx/sizer.h>
#include <wx/textctrl.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/richtext/richtextctrl.h>
#include <wx/choice.h>
#include <wx/thread.h>
#include <iostream>
#include "manager.h"

class Chat : public wxFrame, public wxThread {
    private:
        wxRichTextCtrl* mensagemDisplay; // Mensagem exibida no display
        wxTextCtrl* mensagem; // Mensagem
        wxTextCtrl* destino; // IP destino
        wxButton* configurar; // Botão configurar
        wxButton* enviar; // Botão enviar
        wxChoice* criptografia; // Caixa de seleção para escolher S-DES ou RC4
        wxChoice* modeSdes; // Caixa de seleção para escolher S-DES ou RC4
        wxTextCtrl* chave; // Chave da criptografia
        wxCheckBox* dhCheckBox; // Check box para DH
        Manager manager; // Objeto manager para a comunicação via socket TCP/IP, envio e recepção de mensagens
        bool statusDh = false;

        // Método para o evento enviar
        void BotaoConfigurar(wxCommandEvent& event) {
            // Verificar se o IP destino é válido
            if(!manager.ip_valid(destino->GetValue().ToStdString())) {
                wxMessageBox("Erro: IP destino inválido.", wxT("Erro: IP destino inválido."), wxICON_ERROR | wxOK);
                return;
            }

            // Atribuir o IP de destino
            if(!manager.set_ip(destino->GetValue().ToStdString())) {
                wxMessageBox("Erro: Não foi possível atribuir o IP de destino.", wxT("Erro: Não foi possível atribuir o IP de destino."), wxICON_ERROR | wxOK);
                return;
            }

            // Atribuir a chave de criptografia
            if(!(dhCheckBox->IsChecked())) {
                statusDh = false;
                if(!manager.set_key((chave->GetValue()).ToStdString(), (criptografia->GetString(criptografia->GetSelection()) == wxT("SDES")) ? Manager::encoding::Sdes : Manager::encoding::Rc4)) {
                    wxMessageBox("Erro: Não foi possível atribuir a chave diretamente.", wxT("Erro: Não foi possível atribuir a chave diretamente."), wxICON_ERROR | wxOK);
                    return;
                }
            } else {
                if(!(statusDh)) {
                    if(!manager.dispatch(std::to_string(manager.getPublicKey()), Manager::Dh, Manager::CBC)) {
                        wxMessageBox(wxT("Erro: Não foi possível enviar a chave pública."), wxT("Erro: Não foi possível enviar a chave pública."), wxICON_ERROR | wxOK);
                        return;
                    }

                    std::ostream stream(chave);
                    stream << std::to_string(manager.getSharedKey());
                    statusDh = true;

                    if(!manager.set_key((chave->GetValue()).ToStdString(), (criptografia->GetString(criptografia->GetSelection()) == wxT("SDES")) ? Manager::encoding::Sdes : Manager::encoding::Rc4)) {
                        wxMessageBox("Erro: Não foi possível atribuir a chave compartilhada.", wxT("Erro: Não foi possível atribuir a chave compartilhada."), wxICON_ERROR | wxOK);
                        return;
                    }
                }
            }
        }

        // Método para o evento enviar
        void BotaoEnviar(wxCommandEvent& event) {
            // Verificar se todos os campos foram preenchidos
            if(mensagem->GetValue().IsEmpty() || destino->GetValue().IsEmpty() || (!(dhCheckBox->IsChecked()) && chave->GetValue().IsEmpty())) {
                wxMessageBox("Preencha todos os campos para enviar a mensagem.", "Preencha todos os campos para enviar a mensagem.", wxICON_ERROR | wxOK);
                return;
            }

            // Enviar a mensagem
            if(!manager.dispatch(mensagem->GetValue().ToStdString(), (criptografia->GetString(criptografia->GetSelection()) == wxT("SDES")) ? Manager::encoding::Sdes : Manager::encoding::Rc4, modeSdes->GetString(modeSdes->GetSelection()) == wxT("ECB") ? Manager::smode::ECB : Manager::smode::CBC)) {
                wxMessageBox(wxT("Erro: Não foi possível enviar a mensagem."), wxT("Erro: Não foi possível enviar a mensagem."), wxICON_ERROR | wxOK);
                return;
            }

            // Limpar o text box mensagem
            mensagem->Clear();
        }

    public:
        // Construtor do Chat
        Chat(const wxString& titulo) : wxFrame(nullptr, wxID_ANY, titulo, wxDefaultPosition, wxSize(1200, 600)) {
            if(!manager.start_server()) {
                wxMessageBox("Erro: Não foi possível iniciar o servidor.", wxT("Erro: Não foi possível iniciar o servidor."), wxICON_ERROR | wxOK);
                Close();
                return;
            }

            // Criar um sizer vertical para todos os componentes da GUI
            wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
            // Criar um sizer horizontal para os text box e o botão
            wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);

            // Criar uma label para o text box da mensagem
            wxStaticText* mensLabel = new wxStaticText(this, wxID_ANY, wxT("Mensagem:"));
            // Alterar a cor do texto para preto
            mensLabel->SetForegroundColour(wxColour(0, 0, 0));
            // Inserir a label "Mensagem:" no sizer horizontal
            inputSizer->Add(mensLabel, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um um text box para inserir a mensagem
            mensagem = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
            // Inserir text box da mensagem no sizer horizontal
            inputSizer->Add(mensagem, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);
            mensagem->SetFocus();

            // Criar uma label para inserir o "IP destino"
            wxStaticText* destLabel = new wxStaticText(this, wxID_ANY, wxT("Destino:"));
            // Alterar a cor do texto para preto
            destLabel->SetForegroundColour(wxColour(0, 0, 0));
            // Inserir a label "Destino:" no sizer horizontal
            inputSizer->Add(destLabel, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um text box para inserir o IP destino
            destino = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
            // Inserir o text box do IP destino no sizer horizontal
            inputSizer->Add(destino, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar uma label para escolher a criptografia
            wxStaticText* criptoLabel = new wxStaticText(this, wxID_ANY, wxT("Cripto:"));
            // Altera a cor do texto para preto
            criptoLabel->SetForegroundColour(wxColour(0, 0, 0));
            // Inserir a label "Cripto:" no sizer horizontal
            inputSizer->Add(criptoLabel, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar uma caixa de seleção para a criptografia
            criptografia = new wxChoice(this, wxID_ANY);
            // Inserir os tipos de criptografia S-DES e RC4 à caixa de seleção
            criptografia->Append(wxT("SDES"));
            criptografia->Append(wxT("RC4"));
            // Definir a seleção inicial como "S-DES"
            criptografia->SetSelection(0);
            // Inserir a caixa de seleção da criptografia no sizer horizontal
            inputSizer->Add(criptografia, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar uma label para escolher o modo de operação do S-DES
            wxStaticText* modeLabel = new wxStaticText(this, wxID_ANY, wxT("Mode:"));
            // Altera a cor do texto para preto
            criptoLabel->SetForegroundColour(wxColour(0, 0, 0));
            // Inserir a label "Mode:" no sizer horizontal
            inputSizer->Add(modeLabel, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar uma caixa de seleção para a os modos de operação do S-DES
            modeSdes = new wxChoice(this, wxID_ANY);
            // Inserir os modos de operação ECB e CBC à caixa de seleção
            modeSdes->Append(wxT("ECB"));
            modeSdes->Append(wxT("CBC"));
            // Definir a seleção inicial como "ECB"
            modeSdes->SetSelection(0);
            // Inserir a caixa de seleção dos modos de operação no sizer horizontal
            inputSizer->Add(modeSdes, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar uma label para escolher a criptografia
            wxStaticText* dhLabel = new wxStaticText(this, wxID_ANY, wxT("DH:"));
            // Altera a cor do texto para preto
            criptoLabel->SetForegroundColour(wxColour(0, 0, 0));
            // Inserir a label "Cripto:" no sizer horizontal
            inputSizer->Add(dhLabel, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um check box para DH
            dhCheckBox = new wxCheckBox(this, wxID_ANY, wxT(""));
            inputSizer->Add(dhCheckBox, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar uma label para a chave da criptografia
            wxStaticText* chaveLabel = new wxStaticText(this, wxID_ANY, wxT("Chave:"));
            // Alterar a cor do texto para preto
            chaveLabel->SetForegroundColour(wxColour(0, 0, 0));
            // Inserir a label "Chave:" no sizer horizontal
            inputSizer->Add(chaveLabel, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um text box para inserir a chave da criptografia
            chave = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
            // Inserir o text box da chave da criptografia no sizer horizontal
            inputSizer->Add(chave, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um botão para configurar
            configurar = new wxButton(this, wxID_ANY, wxT("Configurar"));
            configurar->Connect(wxEVT_BUTTON, wxCommandEventHandler(Chat::BotaoConfigurar), NULL, this);
            // Remover a borda do botão
            configurar->SetWindowStyleFlag(wxBORDER_NONE);
            // Inserir o bot�o "Enviar" no sizer horizontal
            inputSizer->Add(configurar, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um botão para enviar a mensagem
            enviar = new wxButton(this, wxID_ANY, wxT("Enviar"));
            enviar->Connect(wxEVT_BUTTON, wxCommandEventHandler(Chat::BotaoEnviar), NULL, this);
            // Remover a borda do botão
            enviar->SetWindowStyleFlag(wxBORDER_NONE);
            // Inserir o bot�o "Enviar" no sizer horizontal
            inputSizer->Add(enviar, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Criar um display para exibir as mensagens
            mensagemDisplay = new wxRichTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY | wxTE_AUTO_URL);
            // Remover a borda
            mensagemDisplay->SetWindowStyleFlag(wxBORDER_NONE);

            // Alterar a cor dos componentes
            SetBackgroundColour(wxColour(2, 31, 38));
            destLabel->SetForegroundColour(wxColour(255, 255, 255));
            mensLabel->SetForegroundColour(wxColour(255, 255, 255));
            criptoLabel->SetForegroundColour(wxColour(255, 255, 255));
            dhLabel->SetForegroundColour(wxColour(255, 255, 255));
            modeLabel->SetForegroundColour(wxColour(255, 255, 255));
            chaveLabel->SetForegroundColour(wxColour(255, 255, 255));
            configurar->SetBackgroundColour(wxColour(2, 104, 115));
            configurar->SetForegroundColour(wxColour(255, 255, 255));
            enviar->SetBackgroundColour(wxColour(2, 104, 115));
            enviar->SetForegroundColour(wxColour(255, 255, 255));
            mensagemDisplay->SetBackgroundColour(wxColour(2, 75, 115));
            mensagemDisplay->SetForegroundColour(wxColour(255, 255, 255));

            // Adiciona o display e o sizer horizontal ao sizer vertical principal
            mainSizer->Add(mensagemDisplay, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);
            mainSizer->Add(inputSizer, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);

            // Definir o sizer principal da janela
            SetSizer(mainSizer);

            // Registrar os eventos dos text box, selection list e do button
            mensagem->Bind(wxEVT_TEXT_ENTER, &Chat::BotaoEnviar, this);
            destino->Bind(wxEVT_TEXT_ENTER, &Chat::BotaoEnviar, this);
            criptografia->Bind(wxEVT_TEXT_ENTER, &Chat::BotaoEnviar, this);
            modeSdes->Bind(wxEVT_TEXT_ENTER, &Chat::BotaoEnviar, this);
            chave->Bind(wxEVT_TEXT_ENTER, &Chat::BotaoEnviar, this);
            configurar->Bind(wxEVT_BUTTON, &Chat::BotaoConfigurar, this);
            enviar->Bind(wxEVT_BUTTON, &Chat::BotaoEnviar, this);

            // Cria a thread para recebimento de mensagem
            if(wxThread::Create() != wxTHREAD_NO_ERROR || wxThread::Run() != wxTHREAD_NO_ERROR) {
                wxMessageBox("Erro: Não foi possível receber a mensagem.", wxT("Erro: Não foi possível receber a mensagem."), wxICON_ERROR | wxOK);
                Close();
            }
        }

        wxThread::ExitCode Entry() override {
            // Instanciar um tipo rich text para definir um estilo para a mensagem
            wxRichTextAttr messageStyle;
            // Mudar cor de fundo da mensagem
            messageStyle.SetBackgroundColour(wxColour(2, 104, 115));
            // Mudar cor do texto
            messageStyle.SetTextColour(wxColour(255, 255, 255));

            while(!wxThread::This()->TestDestroy()) {
                bool received;
                std::string message;
                std::string ip;

                std::tie(received, message, ip) = manager.receive(((criptografia->GetString(criptografia->GetSelection()) == wxT("SDES")) ? Manager::encoding::Sdes : Manager::encoding::Rc4), modeSdes->GetString(modeSdes->GetSelection()) == "ECB" ? Manager::smode::ECB : Manager::smode::CBC);

                if(received) {
                    wxMutexGuiEnter();
                    // Aplicar o estilo
                    mensagemDisplay->BeginStyle(messageStyle);
                        // Imprimir a mensagem no display
                        mensagemDisplay->WriteText(wxString::FromUTF8(ip) + wxT(": ") + wxString::FromUTF8(message) + wxT("\n"));
                    mensagemDisplay->EndStyle();
                    wxMutexGuiLeave();

                    // Rolagem automática do display
                    mensagemDisplay->ShowPosition(mensagemDisplay->GetLastPosition());
                }
                wxThread::Sleep(100);
            }

            return nullptr;
        }
};

class App : public wxApp {
    public:
        bool OnInit() override {
            if(!wxApp::OnInit()) return false;

            Chat* chat = new Chat(wxT("Chat"));
            chat->Show();
            return true;
        }
};

wxIMPLEMENT_APP(App);
