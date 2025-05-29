import subprocess
import re
import os
import sys
from datetime import datetime

def run_nmap(command, output_file=None):
    """执行nmap命令并返回结果"""
    print(f"\n[+] 正在执行: {' '.join(command)}")
    try:
        start_time = datetime.now()
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        output = result.stdout
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"[+] 结果已保存到: {output_file}")
        
        print(f"[+] 命令执行完成，耗时: {execution_time:.2f}秒")
        return output
    except subprocess.CalledProcessError as e:
        print(f"[-] 命令执行失败: {e.stderr}")
        return None

def extract_open_ports(nmap_output, protocol='tcp'):
    """从nmap输出中提取开放端口"""
    pattern = r'(\d+)/' + protocol + r'\s+open'
    ports = re.findall(pattern, nmap_output)
    return ','.join(ports)

def main():
    # 检查是否提供了目标IP
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <目标IP>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    print(f"[+] 开始对 {target_ip} 进行自动渗透测试")
    print(f"[+] 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 创建结果目录
    results_dir = f"results_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(results_dir, exist_ok=True)
    
    # 执行全端口TCP扫描
    print("\n[*] 第一步: 执行全端口TCP扫描")
    tcp_full_scan_file = os.path.join(results_dir, "tcp_full_scan.txt")
    tcp_full_cmd = ["nmap", "--min-rate", "10000", "-p-", target_ip]
    tcp_full_output = run_nmap(tcp_full_cmd, tcp_full_scan_file)
    
    if not tcp_full_output:
        print("[-] TCP全端口扫描失败，退出...")
        sys.exit(1)
    
    # 提取TCP开放端口
    tcp_ports = extract_open_ports(tcp_full_output, 'tcp')
    if not tcp_ports:
        print("[-] 未发现开放的TCP端口")
    else:
        print(f"[+] 发现 {tcp_ports.count(',') + 1} 个开放的TCP端口: {tcp_ports}")
    
    # 执行全端口UDP扫描
    print("\n[*] 第二步: 执行全端口UDP扫描")
    udp_full_scan_file = os.path.join(results_dir, "udp_full_scan.txt")
    udp_full_cmd = ["nmap", "-sU", "--min-rate", "10000", "-p-", target_ip]
    udp_full_output = run_nmap(udp_full_cmd, udp_full_scan_file)
    
    if not udp_full_output:
        print("[-] UDP全端口扫描失败")
    else:
        # 提取UDP开放端口
        udp_ports = extract_open_ports(udp_full_output, 'udp')
        if not udp_ports:
            print("[-] 未发现开放的UDP端口")
        else:
            print(f"[+] 发现 {udp_ports.count(',') + 1} 个开放的UDP端口: {udp_ports}")
    
    # 对开放的TCP端口进行详细扫描
    if tcp_ports:
        print("\n[*] 第三步: 对开放的TCP端口进行详细扫描")
        
        # TCP服务和版本扫描
        tcp_service_scan_file = os.path.join(results_dir, "tcp_service_scan.txt")
        tcp_service_cmd = ["nmap", "-sT", "-sV", "-O", "-p", tcp_ports, target_ip]
        run_nmap(tcp_service_cmd, tcp_service_scan_file)
        
        # TCP漏洞扫描
        tcp_vuln_scan_file = os.path.join(results_dir, "tcp_vuln_scan.txt")
        tcp_vuln_cmd = ["nmap", "--script=vuln", "-p", tcp_ports, target_ip]
        run_nmap(tcp_vuln_cmd, tcp_vuln_scan_file)
    
    # 对开放的UDP端口进行详细扫描
    if udp_ports:
        print("\n[*] 第四步: 对开放的UDP端口进行详细扫描")
        
        # UDP服务和版本扫描
        udp_service_scan_file = os.path.join(results_dir, "udp_service_scan.txt")
        udp_service_cmd = ["nmap", "-sU", "-sV", "-O", "-p", udp_ports, target_ip]
        run_nmap(udp_service_cmd, udp_service_scan_file)
        
        # UDP漏洞扫描
        udp_vuln_scan_file = os.path.join(results_dir, "udp_vuln_scan.txt")
        udp_vuln_cmd = ["nmap", "--script=vuln", "-p", udp_ports, target_ip]
        run_nmap(udp_vuln_cmd, udp_vuln_scan_file)
    
    print(f"\n[+] 渗透测试完成! 所有结果已保存到 {results_dir} 目录")
    print(f"[+] 结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()    
