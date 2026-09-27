# X67 Security iOS — projeto para Netlify

Projeto Vite com funções serverless para autenticação e chaves persistentes. A leitura da sysdiagnose ocorre no navegador; o arquivo **não é enviado ao servidor**.

## Publicação do ZIP

Este ZIP contém o **código-fonte** do projeto. Extraia-o e publique a pasta pelo Netlify CLI ou conecte-a a um repositório Git para ativar as funções de autenticação e gestão de chaves.

```bash
npm install
npx netlify-cli link
npx netlify-cli build
npx netlify-cli deploy --prod
```

O `netlify.toml` aponta o diretório de build `dist` e as funções em `netlify/functions`. O endpoint administrativo já vem com a senha solicitada: **`x67yz`**. Não precisa cadastrar `ADMIN_PASSWORD` ou `SESSION_SECRET` para o primeiro acesso.

Se você já publicou uma versão anterior, publique de novo a versão atualizada do projeto para que o padrão `x67yz` entre no site.

> Aviso: `x67yz` é uma senha curta e fácil de adivinhar. Qualquer pessoa que a conheça poderá abrir o painel e criar ou revogar chaves do seu site. Se quiser trocar mais tarde, cadastre a variável de ambiente `ADMIN_PASSWORD` no Netlify; `SESSION_SECRET` também pode ser definida opcionalmente para separar a chave de sessão da senha administrativa.

**Não arraste somente `dist/` como site estático**: isso não inclui/ativa as funções de autenticação nem o backend de chaves. Para as chaves compartilharem dados entre dispositivos, publique o projeto com as Netlify Functions ativas.

## Teste de build

```bash
npm install
npm run build
```

Para desenvolvimento local, use a Netlify CLI com o site vinculado para que Netlify Blobs esteja disponível.

## Recursos incluídos

- Acesso por chave compartilhada entre dispositivos, com expiração de 1, 3, 7, 15 ou 30 dias, ou permanente.
- Painel administrativo com a senha `x67yz`; geração automática ou personalizada, listagem e revogação de chaves.
- Armazenamento persistente via Netlify Blobs; sessões com cookies HttpOnly, Secure e SameSite.
- Visual preto/vermelho, neve, GIF animado no cabeçalho, tela inicial, análise e relatório JSON baixável.
- Leitura local em streaming de ZIP, TAR/GZIP e sysdiagnose aninhada (GZIP/TAR contendo ZIP), além de log/texto/plist, com limites para arquivo, itens e expansão.
- Relatório enxuto: inventário e eventos de perfil em plist MCState (`SystemProfileRestrictions`, `McProfileEvents.plist`, `MCSettingsEvents.plist`), IDs de perfil explícitos, ferramentas de assinatura, conexões USB confirmadas e lista específica de jailbreak — sem despejar trechos longos do log.

## Limites e interpretação

Esta é uma **triagem heurística**, não uma ferramenta pericial certificada nem uma promessa de zero falso positivo. “Sem evidência encontrada” significa somente que os padrões não apareceram nos dados lidos; não prova que o iPhone esteja limpo. Sinais de USB, ferramenta ou caminho precisam de contexto e confirmação por profissional.

- Limite de arquivo: 2 GiB; limite de dados expandidos: 1 GiB; limite de 10.000 itens ZIP; até 12 MiB processados por arquivo de texto selecionado. Desempenho depende do navegador, memória, CPU e arquivo.
- ZIP e TAR/GZIP — inclusive arquivo ZIP aninhado dentro de TAR.GZ — são lidos em streaming. Alguns TARs GNU/PAX com caminhos incomuns podem não ser reconhecidos nesta edição.
- Plists `bplist00` e XML são examinados para IDs/nome de perfil. Em MCState, perfis instalados/removidos usam os eventos/datas estruturados quando disponíveis; IDs sem evento próprio são marcados como inventário e exibem que o horário não existe no registro.
- `ESign` exige a palavra isolada `ESign`; ocorrências em `CodeSign` não contam. Ferramentas externas e os mesmos nomes próximos de evento de perfil são buscados por palavras delimitadas.
- As ferramentas externas são buscadas pelos nomes solicitados: TrollStore, AltStore, SideStore, Sideloadly, Scarlet, ESign (isolado, sem casar com `CodeSign`), Feather, GBox, TrollHelper, Skibidi Revoke, Khoindvn e KSign.
- Conexão com computador exige evento explícito de USB conectado/pareamento concluído e linha com data/hora; tentativas, USB habilitado, pareamento sem sucesso e menções soltas não contam.
- Jailbreak procura a lista solicitada: Cydia, Sileo, Zebra, Substrate, Substitute, ElleKit, libhooker, TweakInject, RocketBootstrap, Dopamine, palera1n, checkra1n, unc0ver, Taurine e Odyssey.
- As regras pedidas para `freefire`/`freefiremax` buscam também o caminho padrão `logs/Networking/skywalk.txt`; as assinaturas exatas `/McProfileEvents.plist,` e `/McSettingsEvents.plist,` são avaliadas no arquivo `sys/summaries/McState.log`. Uma sysdiagnose que traz somente os plist modernos, sem esse arquivo de resumo, é marcada como suspeita segundo a regra solicitada.
- Os `.tracev3` são arquivos binários de Unified Logging: esta versão procura neles tokens literais, mas não decodifica o formato completo; portanto, mensagens e horários ausentes nesses itens não devem ser tratados como evidência de ausência do evento.
- A capacidade de chaves depende dos limites e armazenamento da conta Netlify; nenhum serviço oferece armazenamento literalmente infinito. Os arquivos sysdiagnose não são guardados pelo app.

## Asset visual

`public/hello-kitty-dance.gif` foi obtido em busca de imagens (origem indicada: Tenor). Confirme as permissões/licença do asset antes da publicação pública.
