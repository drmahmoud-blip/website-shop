/**
 * Supabase Client Configuration & Shared Services
 * متجر لبسني | Labbesni Shop
 */

const SUPABASE_URL = "https://aqjkfvkakxkvbwkthrab.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFxamtmdmtha3hrdmJ3a3RocmFiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTI2MjM0NjksImV4cCI6MjEwODE5OTQ2OX0.vBttqG_kRVcOJil3Qp7al6TAiG83yLJiA2UwYyEcRrw";

// Initialize Supabase client
const db = window.supabase ? window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;

// Status definition with badges, colors, and progress percentage
const ORDER_STATUSES = {
    pending: {
        label: 'قيد الانتظار',
        color: 'bg-amber-100 text-amber-800 border-amber-300',
        badgeClass: 'bg-amber-500',
        stepIndex: 1,
        progressPercent: 25,
        icon: 'fas fa-clock',
        desc: 'تم استلام طلبك وبانتظار المراجعة والتأكيد'
    },
    processing: {
        label: 'جاري التجهيز',
        color: 'bg-blue-100 text-blue-800 border-blue-300',
        badgeClass: 'bg-blue-500',
        stepIndex: 2,
        progressPercent: 50,
        icon: 'fas fa-box-open',
        desc: 'تم تأكيد طلبك وجاري تغليف وتجهيز المنتجات'
    },
    shipped: {
        label: 'تم الشحن',
        color: 'bg-purple-100 text-purple-800 border-purple-300',
        badgeClass: 'bg-purple-500',
        stepIndex: 3,
        progressPercent: 75,
        icon: 'fas fa-shipping-fast',
        desc: 'الشحنة مع مندوب التوصيل في طريقها إليك'
    },
    delivered: {
        label: 'تم التوصيل بنجاح',
        color: 'bg-emerald-100 text-emerald-800 border-emerald-300',
        badgeClass: 'bg-emerald-500',
        stepIndex: 4,
        progressPercent: 100,
        icon: 'fas fa-check-circle',
        desc: 'تم تسليم الشحنة بنجاح. شكراًs'
    },
    cancelled: {
        label: 'ملغي',
        color: 'bg-rose-100 text-rose-800 border-rose-300',
        badgeClass: 'bg-rose-500',
        stepIndex: 0,
        progressPercent: 0,
        icon: 'fas fa-times-circle',
        desc: 'تم إلغاء هذا الطلب'
    }
};

// ==========================================
// SECURITY & INPUT SANITIZATION MODULE
// Protects against XSS, Code Injection & SQLi
// ==========================================
const SecurityHelper = {
    // Hash password using native Web Crypto SHA-256
    async hashPassword(plainText) {
        if (!plainText) return '';
        const encoder = new TextEncoder();
        const data = encoder.encode(plainText);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // Escape HTML special characters for safe DOM rendering
    escapeHTML(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    },

    // Sanitize general text inputs (removes script tags, dangerous HTML, inline event handlers)
    sanitizeText(input, maxLength = 500) {
        if (!input) return '';
        let clean = String(input).trim();

        // Enforce max length
        if (clean.length > maxLength) {
            clean = clean.substring(0, maxLength);
        }

        // Strip HTML tags entirely
        clean = clean.replace(/<[^>]*>?/gm, '');

        // Remove dangerous protocols and keywords
        clean = clean.replace(/javascript:/gi, '');
        clean = clean.replace(/vbscript:/gi, '');
        clean = clean.replace(/data:text\/html/gi, '');
        clean = clean.replace(/onload\s*=/gi, '');
        clean = clean.replace(/onerror\s*=/gi, '');
        clean = clean.replace(/onclick\s*=/gi, '');
        clean = clean.replace(/onmouseover\s*=/gi, '');

        return clean;
    },

    // Strict email validator & sanitizer
    sanitizeEmail(email) {
        if (!email) return '';
        const clean = String(email).trim().toLowerCase();
        // RFC compliant email regex
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
        if (!emailRegex.test(clean)) {
            throw new Error("صيغة البريد الإلكتروني غير صالحة");
        }
        return clean;
    },

    // Strict phone number validator & sanitizer
    sanitizePhone(phone) {
        if (!phone) return '';
        const clean = String(phone).trim();
        // Allow digits, +, -, space, parentheses, length 7 to 20
        const phoneRegex = /^[\+]?[0-9\s\-\(\)]{7,20}$/;
        if (!phoneRegex.test(clean)) {
            throw new Error("رقم الهاتف غير صالح. يرجى إدخال أرقام صحيحة");
        }
        return clean;
    },

    // Detect malicious code injection attempts
    detectMaliciousPayload(input) {
        if (!input) return { safe: true };
        const text = String(input);

        // Common Injection patterns (SQLi, XSS, Command Injection)
        const injectionPatterns = [
            /<script\b[^>]*>([\s\S]*?)<\/script>/i,
            /(UNION\s+SELECT|SELECT\s+.*\s+FROM|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)/i,
            /(1=1|1\s*=\s*1|'\s*OR\s*'1'\s*=\s*'1)/i,
            /<iframe|<object|<embed|<svg.*onload/i,
            /alert\s*\(|prompt\s*\(|confirm\s*\(|document\.cookie/i
        ];

        for (const pattern of injectionPatterns) {
            if (pattern.test(text)) {
                return {
                    safe: false,
                    error: "تم اكتشاف محتوى غير آمن أو محاولة حقن برمجية مرفوضة"
                };
            }
        }
        return { safe: true };
    }
};

// Data service helpers
const ShopDB = {
    // User Authentication & Management
    async checkUserExists(email) {
        if (!db) throw new Error("Supabase client not initialized");
        const cleanEmail = SecurityHelper.sanitizeEmail(email);

        const { data, error } = await db
            .from('app_users')
            .select('id, email, full_name, role, phone')
            .eq('email', cleanEmail)
            .maybeSingle();

        if (error) throw error;
        return data; // Returns user object if exists, null otherwise
    },

    async loginUser(email, password) {
        if (!db) throw new Error("Supabase client not initialized");

        // Anti-injection check
        const emailCheck = SecurityHelper.detectMaliciousPayload(email);
        const passCheck = SecurityHelper.detectMaliciousPayload(password);
        if (!emailCheck.safe) throw new Error(emailCheck.error);
        if (!passCheck.safe) throw new Error(passCheck.error);

        const cleanEmail = SecurityHelper.sanitizeEmail(email);
        const passwordHash = await SecurityHelper.hashPassword(password);

        // 1. Check if user exists in Supabase
        const existingUser = await this.checkUserExists(cleanEmail);
        if (!existingUser) {
            return {
                success: false,
                reason: 'not_found',
                message: 'هذا البريد غير مسجل في Supabase. يرجى إنشاء حساب أولاً.'
            };
        }

        // 2. Verify password hash
        const { data, error } = await db
            .from('app_users')
            .select('id, email, full_name, role, phone')
            .eq('email', cleanEmail)
            .eq('password_hash', passwordHash)
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return {
                success: false,
                reason: 'wrong_password',
                message: 'كلمة المرور غير صحيحة. يرجى المحاولة مرة أخرى.'
            };
        }

        // 3. Update last login
        await db.from('app_users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', data.id);

        // 4. Save Session
        const sessionData = {
            id: data.id,
            email: data.email,
            name: data.full_name,
            role: data.role,
            phone: data.phone,
            loginTime: Date.now()
        };
        localStorage.setItem('labbesni_session', JSON.stringify(sessionData));

        return {
            success: true,
            user: sessionData
        };
    },

    async registerUser({ email, password, full_name, phone }) {
        if (!db) throw new Error("Supabase client not initialized");

        // Anti-injection check
        const fields = [email, password, full_name, phone];
        for (const f of fields) {
            const check = SecurityHelper.detectMaliciousPayload(f);
            if (!check.safe) throw new Error(check.error);
        }

        const cleanEmail = SecurityHelper.sanitizeEmail(email);
        const cleanName = SecurityHelper.sanitizeText(full_name, 100);
        const cleanPhone = phone ? SecurityHelper.sanitizePhone(phone) : '';

        if (!password || password.length < 5) {
            throw new Error("كلمة المرور يجب ألا تقل عن 5 خانات");
        }

        // Check if email already registered
        const existing = await this.checkUserExists(cleanEmail);
        if (existing) {
            throw new Error("هذا البريد الإلكتروني مسجل بالفعل! يرجى تسجيل الدخول.");
        }

        const passwordHash = await SecurityHelper.hashPassword(password);

        // Insert new user
        const { data, error } = await db
            .from('app_users')
            .insert([{
                email: cleanEmail,
                password_hash: passwordHash,
                full_name: cleanName,
                phone: cleanPhone,
                role: 'user'
            }])
            .select('id, email, full_name, role, phone')
            .single();

        if (error) throw error;

        // Auto login
        const sessionData = {
            id: data.id,
            email: data.email,
            name: data.full_name,
            role: data.role,
            phone: data.phone,
            loginTime: Date.now()
        };
        localStorage.setItem('labbesni_session', JSON.stringify(sessionData));

        return {
            success: true,
            user: sessionData
        };
    },

    getCurrentUser() {
        try {
            const raw = localStorage.getItem('labbesni_session');
            if (!raw) return null;
            return JSON.parse(raw);
        } catch(e) {
            return null;
        }
    },

    logout() {
        localStorage.removeItem('labbesni_session');
        window.location.href = 'login.html';
    },

    requireAdmin(redirectUrl = 'login.html') {
        const user = this.getCurrentUser();
        if (!user || user.role !== 'admin') {
            alert('عفواً، الدخول إلى لوحة التحكم يتطلب حساب مدير النظام [admin@lab.com].');
            window.location.href = redirectUrl;
            return false;
        }
        return true;
    },

    requireAuth(redirectUrl = 'login.html') {
        const user = this.getCurrentUser();
        if (!user) {
            window.location.href = redirectUrl;
            return false;
        }
        return true;
    },

    // Categories
    async getCategories() {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('categories')
            .select('*')
            .order('display_order', { ascending: true });
        if (error) throw error;
        return data;
    },

    async addCategory(category) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('categories')
            .insert([category])
            .select();
        if (error) throw error;
        return data[0];
    },

    async updateCategory(id, updates) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('categories')
            .update(updates)
            .eq('id', id)
            .select();
        if (error) throw error;
        return data[0];
    },

    async deleteCategory(id) {
        if (!db) throw new Error("Supabase client not initialized");
        const { error } = await db
            .from('categories')
            .delete()
            .eq('id', id);
        if (error) throw error;
        return true;
    },

    // Products
    async getProducts(categoryId = null) {
        if (!db) throw new Error("Supabase client not initialized");
        let query = db.from('products').select('*').order('id', { ascending: false });
        if (categoryId && categoryId !== 'all') {
            query = query.eq('category', categoryId);
        }
        const { data, error } = await query;
        if (error) throw error;
        return data;
    },

    async getProductById(id) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('products')
            .select('*')
            .eq('id', id)
            .single();
        if (error) throw error;
        return data;
    },

    async addProduct(product) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('products')
            .insert([product])
            .select();
        if (error) throw error;
        return data[0];
    },

    async updateProduct(id, updates) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('products')
            .update(updates)
            .eq('id', id)
            .select();
        if (error) throw error;
        return data[0];
    },

    async deleteProduct(id) {
        if (!db) throw new Error("Supabase client not initialized");
        const { error } = await db
            .from('products')
            .delete()
            .eq('id', id);
        if (error) throw error;
        return true;
    },

    // Upload Product Image to Supabase Storage Bucket
    async uploadProductImage(file) {
        if (!db) throw new Error("Supabase client not initialized");

        // Generate unique clean file name
        const ext = file.name.split('.').pop() || 'jpg';
        const cleanName = `${Date.now()}_${Math.random().toString(36).substring(2, 7)}.${ext}`;
        const filePath = `items/${cleanName}`;

        const { data, error } = await db.storage
            .from('product-images')
            .upload(filePath, file, {
                cacheControl: '3600',
                upsert: true
            });

        if (error) {
            console.error("Storage upload error, falling back to base64 if needed:", error);
            throw error;
        }

        // Retrieve public URL
        const { data: urlData } = db.storage
            .from('product-images')
            .getPublicUrl(filePath);

        return urlData.publicUrl;
    },

    // Orders & Tracking
    async getOrders() {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('orders')
            .select('*')
            .order('created_at', { ascending: false });
        if (error) throw error;
        return data;
    },

    async getOrderById(id) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('orders')
            .select('*')
            .eq('id', id)
            .single();
        if (error) throw error;
        return data;
    },

    async getOrdersByPhone(phone) {
        if (!db) throw new Error("Supabase client not initialized");
        const cleanPhone = phone.trim();
        const { data, error } = await db
            .from('orders')
            .select('*')
            .ilike('customer_phone', `%${cleanPhone}%`)
            .order('created_at', { ascending: false });
        if (error) throw error;
        return data;
    },

    async createOrder(orderData) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('orders')
            .insert([orderData])
            .select();
        if (error) throw error;
        return data[0];
    },

    async updateOrderStatus(id, newStatus) {
        if (!db) throw new Error("Supabase client not initialized");
        const { data, error } = await db
            .from('orders')
            .update({ status: newStatus, updated_at: new Date().toISOString() })
            .eq('id', id)
            .select();
        if (error) throw error;
        return data[0];
    }
};

window.ShopDB = ShopDB;
window.ORDER_STATUSES = ORDER_STATUSES;
window.SecurityHelper = SecurityHelper;
