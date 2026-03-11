package org.example.input_security_starter.tracker;

/**
 * 攻击阶段枚举
 * 基于 Cyber Kill Chain 简化模型，用于追踪攻击者的攻击进度
 * 
 * 攻击链阶段：
 * 1. RECONNAISSANCE - 侦察：信息收集、扫描探测
 * 2. DELIVERY - 投递：攻击载荷投递（XSS、SQL注入尝试）
 * 3. EXPLOITATION - 利用：成功利用漏洞（命令执行、代码执行）
 * 4. INSTALLATION - 安装：植入后门、webshell
 * 5. COMMAND_CONTROL - 命令控制：反向连接、C2通信
 * 6. ACTIONS - 行动：数据窃取、破坏、横向移动
 */
public enum AttackPhase {
    
    /** 侦察阶段：信息收集、扫描探测 */
    RECONNAISSANCE(1, "reconnaissance", 10, "侦察"),
    
    /** 投递阶段：攻击载荷投递 */
    DELIVERY(2, "delivery", 30, "投递"),
    
    /** 利用阶段：漏洞利用、代码执行 */
    EXPLOITATION(3, "exploitation", 50, "利用"),
    
    /** 安装阶段：植入后门、webshell */
    INSTALLATION(4, "installation", 70, "安装"),
    
    /** 命令控制阶段：反向连接、C2通信 */
    COMMAND_CONTROL(5, "command_control", 85, "命令控制"),
    
    /** 行动阶段：数据窃取、破坏 */
    ACTIONS(6, "actions", 100, "行动");
    
    /** 阶段序号，用于比较阶段先后 */
    private final int order;
    
    /** 阶段标识，用于日志输出 */
    private final String id;
    
    /** 基础风险分，用于计算累积风险 */
    private final int baseScore;
    
    /** 阶段中文名称 */
    private final String displayName;
    
    AttackPhase(int order, String id, int baseScore, String displayName) {
        this.order = order;
        this.id = id;
        this.baseScore = baseScore;
        this.displayName = displayName;
    }
    
    public int getOrder() { return order; }
    public String getId() { return id; }
    public int getBaseScore() { return baseScore; }
    public String getDisplayName() { return displayName; }
    
    /**
     * 判断当前阶段是否在目标阶段之后
     * @param other 目标阶段
     * @return 是否在目标阶段之后
     */
    public boolean isAfter(AttackPhase other) {
        return this.order > other.order;
    }
    
    /**
     * 判断当前阶段是否在目标阶段之前
     * @param other 目标阶段
     * @return 是否在目标阶段之前
     */
    public boolean isBefore(AttackPhase other) {
        return this.order < other.order;
    }
    
    /**
     * 计算与目标阶段的距离
     * @param other 目标阶段
     * @return 阶段距离（正数表示在目标之后，负数表示在目标之前）
     */
    public int distance(AttackPhase other) {
        return this.order - other.order;
    }
}
