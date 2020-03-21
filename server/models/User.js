const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true, // 문자 간 스페이스를 없애는 역할을 함
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        dafault: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
});
// .pre 메소드 : 데이터베이스 입력값을 '저장'하기 전에 callback 함수값을 처리하는 뜻
userSchema.pre("save", function(next) {
    var user = this; // 위 스키마를 가르킴

    // 비밀번호를 바꾸는건 비밀번호가 수정될 때 적용되어야 하기 때문에 조건을 하나 더 걸어준다.
    if (user.isModified("password")) {
        // salt를 이용해서 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if (err) return next(err);

            bcrypt.hash(user.password, salt, function(err, hash) {
                if (err) return next(err);
                user.password = hash;
                next(); // 완성이 되었으면 돌아감
            });
        });
    } else {
        next(); // 다른것만 바꿀 때 다음으로 넘겨야 하므로 필요함
    }
});

userSchema.methods.comparePassword = function(plainPassword, cb) {
    // plainPassword 1234567 암호화된 비밀번호 $2b$10$9gvuDlJ0ywupQ8jVBUlFTOx1Jeuk5K73AALF0TB/UIs6wc.uoGxs.
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch); // err는 없고, isMatch는 true값이 들어오게 된다.
    });
};

userSchema.methods.generateToken = function(cb) {
    var user = this;

    // jsonwebtoken을 이용해서 token을 생성하기
    var token = jwt.sign(user._id.toHexString(), "secretToken"); // 원리는 두개를 합쳐서 토큰을 만들고 나중에 decoding 과정을 거칠 때 secretToken을 넣으면 user._id 값이 나온다고 생각하기

    user.token = token;
    user.save(function(err, user) {
        if (err) return cb(err);
        cb(null, user);
    });
};

userSchema.statics.findByToken = function(token, cb) {
    var user = this;

    // 토큰을 decode 한다.
    jwt.verify(token, "secretToken", function(err, decoded) {
        // 유저 아이디를 이용해서 유저를 찾은 다음에
        // 클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인

        user.findOne({ _id: decoded, token: token }, function(err, user) {
            if (err) return cb(err);
            cb(null, user);
        });
    });
};

// 이 스키마를 모델로 감싸주는 것
const User = mongoose.model("User", userSchema);

// 이 모델을 다른 파일에서도 쓸 수있게 하는 것
module.exports = { User };
