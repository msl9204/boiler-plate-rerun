const express = require("express");
const app = express();
const port = 5000;
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const config = require("./config/key");
const { auth } = require("./middleware/auth");
const { User } = require("./models/User");

// application/x-www-form-urlencoded로 된 데이터를 분석해서 가져올 수 있게 해주는 것.
app.use(bodyParser.urlencoded({ extended: true }));
// application/json 타입의 데이터를 가져올 수 있게 하는 부분.
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require("mongoose");
mongoose
    .connect(config.mongoURL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true,
        useFindAndModify: false
    })
    .then(() => console.log("MongoDB Connected..."))
    .catch(err => console.log(err));

app.get("/", (req, res) => res.send("Hello World!"));

app.post("/api/users/register", (req, res) => {
    // 회원가입 할때 필요한 정보들을 Client에서 가져오면
    // 그것들을 데이터 베이스에 넣어준다.
    // req.body는 body-parser 때문에 쓸 수 있다.
    const user = new User(req.body); // 데이터베이스에 넣는 과정이라고 생각하기

    user.save((err, userInfo) => {
        // user.save 메소드는 mongoose에서 온 것이다.
        // 에러가 있다면 res 객체에 false값과 err 전달.
        if (err) return res.json({ success: false, err });
        // 에러가 없다면 res객체에 true값 전달.
        return res.status(200).json({
            success: true
        });
    });
});

app.post("/api/users/login", (req, res) => {
    // 요청된 이메일을 데이터베이스에서 있는지 찾는다.
    User.findOne({ email: req.body.email }, (err, user) => {
        if (!user) {
            return res.json({
                loginSuccess: false,
                message: "제공된 이메일에 해당하는 유저가 없습니다."
            });
        }
        // 요청된 이메일이 데이터베이스에 있다면 비밀번호가 맞는 비밀번호 인지 확인.
        user.comparePassword(req.body.password, (err, isMatch) => {
            if (!isMatch)
                return res.json({
                    loginSuccess: false,
                    message: "비밀번호가 틀렸습니다."
                });
            // 비밀번호까지 맞다면, 토큰을 생성하기.
            user.generateToken((err, user) => {
                if (err) return res.status(400).send(err);

                // 토큰을 저장한다. 어디에? 쿠키, 로컬스토리지 등등
                res.cookie("x_auth", user.token)
                    .status(200)
                    .json({ loginSuccess: true, userId: user._id });
            });
        });
    });
});

// 여기서 auth는 미들웨어이다. req, res 콜백함수 수행 전 처리하는 개념
app.get("/api/users/auth", auth, (req, res) => {
    // 여기까지 미들웨어를 통과해 왔다는 얘기는 Authentication이 True라는 말.
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    });
});

// 로그아웃 구현
// 아직 로그인된 상태이기 때문에 auth 미들웨어를 중간에 넣어준다.
app.get("/api/users/logout", auth, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id }, { token: "" }, (err, user) => {
        if (err) return res.json({ success: false });
        return res.status(200).send({ success: true });
    });
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
