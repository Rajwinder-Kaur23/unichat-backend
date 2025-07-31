const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const options = { discriminatorKey: 'role', timestamps: true };

let User;

// Only compile the model if it hasn't been compiled already
if (mongoose.models.User) {
  User = mongoose.model('User');
} else {
  const userSchema = new mongoose.Schema(
    {
      firstName: { type: String, required: true, trim: true },
      lastName: { type: String, trim: true },

      username: {
        type: String,
        required: true,
        unique: true,
        minlength: 5,
        trim: true,
        validate: {
          validator: function (v) {
            return /^[a-zA-Z0-9]+[_.]?[a-zA-Z0-9]+$/.test(v);
          },
          message: 'Username must be at least 5 characters... ',
        },
      },

      email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        validate: {
          validator: function (email) {
            return /.+@.+\..+/.test(email);
          },
          message: (props) => ${props.value} is not a valid email address.,
        },
      },

      password: {
        type: String,
        required: true,
        minlength: 7,
        validate: {
          validator: function (v) {
            return /^(?=.[a-z])(?=.[A-Z])(?=.[!@#$%^&])(?=.*\d).{7,}$/.test(v);
          },
          message:
            'Password must contain at least 1 lowercase, 1 uppercase, 1 number, 1 special character (!@#$%^&*), and be more than 7 characters',
        },
      },

      bio: { type: String, default: '' },

      role: {
        type: String,
        enum: ['Student', 'Mentor', 'Alumni'],
        required: true,
      },

      programType: {
        type: String,
        enum: [
          'Certificate',
          'Diploma',
          'Baccalaureate Degree',
          'Post Baccalaureate Diploma',
          'Graduate Diploma',
          'Graduate Certificate',
          'Associate Degree',
          'Continuing and Professional Studies',
          'Other',
        ],
        index: true,
      },

      program: {
        type: String,
        ref: 'program',
      },

      coursesEnrolled: [
        {
          course: {
            type: String,
            ref: 'course',
          },
          semester: {
            type: String,
            enum: ['Fall', 'Spring', 'Summer'],
          },
          year: {
            type: Number,
          },
          instructor: {
            type: String,
          },
        },
      ],

      isVerified: {
        type: Boolean,
        default: false,
      },
      isApproved: {
        type: Boolean,
        default: false,
      },
    },
    options
  );

  userSchema.virtual('fullName').get(function () {
    return ${this.firstName} ${this.lastName};
  });

  userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
      const saltRounds = 10;
      this.password = await bcrypt.hash(this.password, saltRounds);
      next();
    } catch (err) {
      next(err);
    }
  });

  User = mongoose.model('User', userSchema);
}

module.exports = User;
