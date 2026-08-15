const state = { token: sessionStorage.getItem('vpsGuardToken') || '', data: {}, view: 'overview' };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(`/api/${path}`, { ...options, headers: { 'Content-Type': 'application/json', 'X-Panel-Token': state.token, ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) throw new Error('访问令牌无效');
  if (!response.ok) throw new Error(body.error || body.output || '请求失败');
  return body;
}

function toast(message, error = false) {
  const node = $('#toast'); node.textContent = message; node.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => node.className = 'toast', 3000);
}

function duration(seconds) {
  const days = Math.floor(seconds / 86400), hours = Math.floor((seconds % 86400) / 3600), mins = Math.floor((seconds % 3600) / 60);
  return days ? `${days} 天 ${hours} 小时` : `${hours} 小时 ${mins} 分`;
}

function setMetric(name, value) {
  $(`#${name}Value`).textContent = `${value}%`; $(`#${name}Bar`).style.width = `${value}%`;
  $(`#${name}Bar`).style.background = value >= 85 ? '#b43b38' : value >= 70 ? '#b66a16' : '#167a5a';
}

function badge(active, yes = '运行中', no = '未运行') { return `<span class="state-badge${active ? '' : ' off'}">${active ? yes : no}</span>`; }

function renderOverview(data) {
  $('#hostname').textContent = data.hostname; $('#platform').textContent = data.platform; $('#kernel').textContent = data.kernel;
  $('#uptime').textContent = duration(data.uptime); $('#load').textContent = data.load.join(' / ');
  setMetric('cpu', data.cpu); setMetric('memory', data.memory); setMetric('disk', data.disk);
  const labels = { ssh: ['SSH 服务', '远程访问入口', 'S'], fail2ban: ['Fail2Ban', '暴力破解防护', 'F'], docker: ['Docker', '容器运行环境', 'D'] };
  $('#serviceList').innerHTML = Object.entries(data.services).map(([key, value]) => `<div class="service"><div class="service-name"><span class="service-icon">${labels[key][2]}</span><div><strong>${labels[key][0]}</strong><small>${labels[key][1]}</small></div></div>${badge(value === 'active')}</div>`).join('');
}

function renderBaseline() {
  const ssh = state.data.ssh, fw = state.data.firewall, ban = state.data.fail2ban, network = state.data.network;
  const checks = [
    [fw.active, '防火墙已启用', fw.active ? `${fw.provider} 正在保护入站流量` : '建议立即启用主机防火墙'],
    [ssh && !ssh.password_auth, 'SSH 密码认证', ssh && !ssh.password_auth ? '已关闭，使用密钥认证' : '仍允许密码登录'],
    [ban.active, '暴力破解防护', ban.active ? 'Fail2Ban sshd 监狱运行中' : 'Fail2Ban 未运行'],
    [ssh && ssh.root_login !== 'yes', 'Root 登录策略', ssh ? `当前策略：${ssh.root_login}` : '读取失败']
    ,[network && network.public_count === 0, '公网暴露面', network ? `${network.public_count} 个公网监听端口` : '读取失败']
  ];
  const passed = checks.filter(item => item[0]).length;
  $('#score').textContent = `${Math.round(passed / checks.length * 100)}%`;
  $('#checkList').innerHTML = checks.map(item => `<div class="check${item[0] ? '' : ' warn'}"><i>${item[0] ? '✓' : '!'}</i><div><strong>${item[1]}</strong><small>${item[2]}</small></div></div>`).join('');
}

function renderNetwork(data) {
  $('#publicPorts').textContent = data.public_count;
  $('#listeningPorts').textContent = data.listening.length;
  $('#networkTool').textContent = data.available ? data.tool : '--';
  const labels = { critical: '高风险', high: '需关注', medium: '有限暴露', low: '未发现', unknown: '不可用' };
  $('#networkRisk').textContent = labels[data.risk] || data.risk;
  $('#networkRisk').className = `state-badge${['critical', 'high'].includes(data.risk) ? ' off' : ''}`;
  $('#networkTable').innerHTML = data.listening.length ? data.listening.map(item => `<tr><td>${escapeHtml(item.protocol.toUpperCase())}</td><td class="mono">${escapeHtml(item.address)}</td><td><strong>${item.port}</strong></td><td><span class="risk ${item.public ? 'high' : 'low'}">${item.public ? '公网' : '回环'}</span></td></tr>`).join('') : '<tr><td colspan="4" class="empty">暂未读取到监听端口</td></tr>';
}

function renderFirewall(data) {
  $('#firewallState').textContent = data.active ? '防护中' : '未启用'; $('#firewallState').className = `state-badge${data.active ? '' : ' off'}`;
  $('#firewallProvider').textContent = data.provider; $('#firewallRules').innerHTML = data.rules.length ? data.rules.map(rule => `<div class="rule">${escapeHtml(rule)}</div>`).join('') : '<div class="empty">暂无防火墙规则</div>';
}

function renderSsh(data) {
  const details = [['监听端口', data.port], ['密码认证', data.password_auth ? '已开启' : '已关闭'], ['Root 登录', data.root_login], ['授权密钥', `${data.keys} 个`]];
  $('#sshDetails').innerHTML = details.map(item => `<article class="detail-card"><span>${item[0]}</span><strong>${escapeHtml(String(item[1]))}</strong></article>`).join('');
}

function renderFail2ban(data) {
  $('#banCount').textContent = data.total; $('#banState').textContent = data.active ? '运行中' : (data.installed ? '已停止' : '未安装');
  $('#banTable').innerHTML = data.banned.length ? data.banned.map(ip => `<tr><td class="mono">${escapeHtml(ip)}</td><td>sshd</td><td><button class="secondary unban" data-ip="${escapeHtml(ip)}">解除封禁</button></td></tr>`).join('') : '<tr><td colspan="3" class="empty">当前没有被封禁的地址</td></tr>';
}

function renderBruteForce(data) {
  $('#bruteAttempts').textContent = data.total_attempts;
  $('#bruteIps').textContent = data.unique_ips;
  $('#bruteSource').textContent = data.log_source === '未找到 SSH 认证日志' ? '--' : data.log_source.replace('/var/log/', '');
  $('#bruteAvailability').textContent = data.available ? '日志读取正常' : '未找到认证日志';
  $('#bruteTable').innerHTML = data.top_ips.length ? data.top_ips.map(item => `<tr><td class="mono">${escapeHtml(item.ip)}</td><td><strong>${item.attempts}</strong></td><td>${escapeHtml(item.usernames.join(', '))}</td><td class="mono">${escapeHtml(item.last_seen)}</td><td><span class="risk ${item.risk}">${item.risk === 'critical' ? '严重' : item.risk === 'high' ? '高' : item.risk === 'medium' ? '中' : '低'}</span></td><td><button class="danger ban-ip" data-ip="${escapeHtml(item.ip)}">封禁 IP</button></td></tr>`).join('') : '<tr><td colspan="6" class="empty">暂未发现 SSH 失败登录记录</td></tr>';
}

function renderUsers(data) {
  $('#usersTable').innerHTML = data.length ? data.map(user => `<tr><td><strong>${escapeHtml(user.name)}</strong></td><td>${user.uid}</td><td class="mono">${escapeHtml(user.home)}</td><td class="mono">${escapeHtml(user.shell)}</td><td><button class="secondary lock-user" data-user="${escapeHtml(user.name)}">锁定</button></td></tr>`).join('') : '<tr><td colspan="5" class="empty">没有普通用户</td></tr>';
}

function renderAudit(data) {
  $('#auditList').innerHTML = data.length ? data.map(item => `<div class="audit-item"><span class="audit-time">${new Date(item.time * 1000).toLocaleString()}</span><i class="audit-node${item.ok ? '' : ' fail'}"></i><div><strong>${escapeHtml(item.action)} · ${item.ok ? '成功' : '失败'}</strong><p>${escapeHtml(item.detail || '')}</p></div></div>`).join('') : '<div class="empty">尚无面板操作记录</div>';
}

function escapeHtml(value) { const node = document.createElement('span'); node.textContent = value; return node.innerHTML; }

async function loadAll() {
  const names = ['overview', 'ssh', 'firewall', 'network', 'fail2ban', 'bruteforce', 'users', 'audit'];
  const values = await Promise.all(names.map(name => api(name)));
  names.forEach((name, index) => state.data[name] = values[index]);
  renderOverview(state.data.overview); renderSsh(state.data.ssh); renderFirewall(state.data.firewall); renderNetwork(state.data.network); renderFail2ban(state.data.fail2ban); renderBruteForce(state.data.bruteforce); renderUsers(state.data.users); renderAudit(state.data.audit); renderBaseline();
  $('#updatedAt').textContent = `更新于 ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}

function showView(name) {
  const titles = { overview: ['SECURITY OVERVIEW', '安全总览'], firewall: ['NETWORK POLICY', '防火墙'], network: ['ATTACK SURFACE', '网络暴露面'], ssh: ['REMOTE ACCESS', 'SSH 安全'], fail2ban: ['INTRUSION PREVENTION', '入侵防护'], bruteforce: ['THREAT DETECTION', '爆破检测'], users: ['ACCESS CONTROL', '用户权限'], audit: ['AUDIT TRAIL', '审计日志'] };
  state.view = name; $$('.view').forEach(view => view.classList.toggle('active', view.id === `view-${name}`)); $$('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.view === name));
  $('#viewEyebrow').textContent = titles[name][0]; $('#viewTitle').textContent = titles[name][1]; $('.sidebar').classList.remove('open');
}

async function perform(action, args = {}) {
  const dialog = $('#confirmDialog'); $('#confirmText').textContent = `即将执行 ${action}，操作会写入审计日志。`;
  dialog.showModal(); const accepted = await new Promise(resolve => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true }));
  if (!accepted) return;
  try { const result = await api('action', { method: 'POST', body: JSON.stringify({ action, args, confirm: 'CONFIRM' }) }); toast(result.output || '操作已完成'); await loadAll(); } catch (error) { toast(error.message, true); }
}

$('#loginForm').addEventListener('submit', async event => { event.preventDefault(); state.token = $('#token').value.trim(); try { await api('overview'); sessionStorage.setItem('vpsGuardToken', state.token); $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); await loadAll(); } catch (error) { $('#loginError').textContent = error.message; state.token = ''; } });
$('#refresh').addEventListener('click', () => loadAll().then(() => toast('数据已刷新')).catch(error => toast(error.message, true)));
$('#logout').addEventListener('click', () => { sessionStorage.removeItem('vpsGuardToken'); location.reload(); });
$('#menuButton').addEventListener('click', () => $('.sidebar').classList.toggle('open'));
$('#nav').addEventListener('click', event => { const button = event.target.closest('[data-view]'); if (button) showView(button.dataset.view); });
document.addEventListener('click', event => { const jump = event.target.closest('[data-jump]'); if (jump) showView(jump.dataset.jump); const action = event.target.closest('.action'); if (action) perform(action.dataset.action); const unban = event.target.closest('.unban'); if (unban) perform('unban_ip', { ip: unban.dataset.ip }); const ban = event.target.closest('.ban-ip'); if (ban) perform('ban_ip', { ip: ban.dataset.ip }); const lock = event.target.closest('.lock-user'); if (lock) perform('lock_user', { user: lock.dataset.user }); });
$('#portForm').addEventListener('submit', event => { event.preventDefault(); const form = new FormData(event.currentTarget); perform(form.get('mode'), { port: form.get('port') }); });
$('#refreshBrute').addEventListener('click', () => loadAll().then(() => toast('爆破检测已刷新')).catch(error => toast(error.message, true)));

if (state.token) { $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); loadAll().catch(() => { sessionStorage.removeItem('vpsGuardToken'); location.reload(); }); }
