# Code Citations

## License: unknown
https://github.com/rigox/bootcamp_api/blob/5a672314b3fb167440bb6766cf462603c812c458/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/FeroHriadel/needfulthings/blob/70019cbed83e957906b071c59847527459ee6409/backend/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/TSOlami/jwt-mern-app/blob/b56e7b83f97ae386c1b7b0fe2c5c1a5274fdee10/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/field-linker/blob/8bf227ff925cda09a133de64a7ee9ebb880d1fe8/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/backend/blob/e02f84b658831e26a01f53b3ab79c5e3026701ff/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/backend/blob/e02f84b658831e26a01f53b3ab79c5e3026701ff/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/rigox/bootcamp_api/blob/5a672314b3fb167440bb6766cf462603c812c458/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/FeroHriadel/needfulthings/blob/70019cbed83e957906b071c59847527459ee6409/backend/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/TSOlami/jwt-mern-app/blob/b56e7b83f97ae386c1b7b0fe2c5c1a5274fdee10/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/field-linker/blob/8bf227ff925cda09a133de64a7ee9ebb880d1fe8/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/backend/blob/e02f84b658831e26a01f53b3ab79c5e3026701ff/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/rigox/bootcamp_api/blob/5a672314b3fb167440bb6766cf462603c812c458/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/FeroHriadel/needfulthings/blob/70019cbed83e957906b071c59847527459ee6409/backend/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/TSOlami/jwt-mern-app/blob/b56e7b83f97ae386c1b7b0fe2c5c1a5274fdee10/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/field-linker/blob/8bf227ff925cda09a133de64a7ee9ebb880d1fe8/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/field-linker/blob/8bf227ff925cda09a133de64a7ee9ebb880d1fe8/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
```


## License: unknown
https://github.com/nithushna-s/backend/blob/e02f84b658831e26a01f53b3ab79c5e3026701ff/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
```


## License: unknown
https://github.com/rigox/bootcamp_api/blob/5a672314b3fb167440bb6766cf462603c812c458/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
```


## License: unknown
https://github.com/FeroHriadel/needfulthings/blob/70019cbed83e957906b071c59847527459ee6409/backend/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
```


## License: unknown
https://github.com/TSOlami/jwt-mern-app/blob/b56e7b83f97ae386c1b7b0fe2c5c1a5274fdee10/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
```


## License: unknown
https://github.com/rigox/bootcamp_api/blob/5a672314b3fb167440bb6766cf462603c812c458/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/FeroHriadel/needfulthings/blob/70019cbed83e957906b071c59847527459ee6409/backend/models/User.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/TSOlami/jwt-mern-app/blob/b56e7b83f97ae386c1b7b0fe2c5c1a5274fdee10/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/field-linker/blob/8bf227ff925cda09a133de64a7ee9ebb880d1fe8/backend/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/nithushna-s/backend/blob/e02f84b658831e26a01f53b3ab79c5e3026701ff/models/userModel.js

```
before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
module.exports =
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ruhstratp/SkinTerra-WebApp/blob/d9413196b8c71be9d299b9cbb9d0e081e66a43f5/auth/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ruhstratp/SkinTerra-WebApp/blob/d9413196b8c71be9d299b9cbb9d0e081e66a43f5/auth/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ruhstratp/SkinTerra-WebApp/blob/d9413196b8c71be9d299b9cbb9d0e081e66a43f5/auth/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/ruhstratp/SkinTerra-WebApp/blob/d9413196b8c71be9d299b9cbb9d0e081e66a43f5/auth/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ruhstratp/SkinTerra-WebApp/blob/d9413196b8c71be9d299b9cbb9d0e081e66a43f5/auth/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/OliverMensahDev/software-engineering/blob/4b58822cce3163339e7429acdb3202e99333fae5/programming-languages/Nodejs/Express/Authentication-Users-Permissions/08-User-CRUD/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/eliavco/NodeJsJonas/blob/3da38f957c7717008a90d689c589296f71a3090d/complete-node-bootcamp-master/4-natours/starter/controllers/authController.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/masiucd/recursive-render/blob/cf50e7233cb5587cc0e6d403de65bd1d8cce6a7a/src/api_helpers/useAuth.ts

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/oluwasheeun/sendIT/blob/4a89a6b22d59fdcf39bf2117fa933e95cc522698/middleware/auth.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ajitpradhan925/NewsAppApiDev/blob/083dd2819964384e5defb9d5590dd5b6092b368d/middleware/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ZorikovPasha/React-Loft-Mebel/blob/bb97601138bcfa980dee55f2ae89f6bba6496dcc/server/middleware/protect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/uriee/kibbutznik_app/blob/7794caf7ac747f60b00cd0e96dc958535018706a/scr/middlewares/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/ruhstratp/SkinTerra-WebApp/blob/d9413196b8c71be9d299b9cbb9d0e081e66a43f5/auth/authMiddleware.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```


## License: unknown
https://github.com/A-Patel033/MERN-Stack-JWT-Authentication/blob/b6e0e76583cee9c1b6fbb31326ac7fbd971c919b/middleware/authProtect.js

```
const User = require('../models/UserModel');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.
```

