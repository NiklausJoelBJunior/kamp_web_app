const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const organizationMemberSchema = new mongoose.Schema(
  {
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["admin", "member", "viewer"],
      default: "member",
    },
    permissions: {
      canViewDashboard: { type: Boolean, default: true },
      canViewProjects: { type: Boolean, default: true },
      canViewMyProjects: { type: Boolean, default: true },
      canManageMembers: { type: Boolean, default: false },
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

// Create compound index for organization + email uniqueness
organizationMemberSchema.index({ organizationId: 1, email: 1 }, { unique: true });

// Hash password before saving
organizationMemberSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Method to compare password
organizationMemberSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Set permissions based on role
organizationMemberSchema.pre("save", function (next) {
  if (this.isModified("role")) {
    switch (this.role) {
      case "admin":
        this.permissions = {
          canViewDashboard: true,
          canViewProjects: true,
          canViewMyProjects: true,
          canManageMembers: true,
        };
        break;
      case "member":
        this.permissions = {
          canViewDashboard: true,
          canViewProjects: true,
          canViewMyProjects: true,
          canManageMembers: false,
        };
        break;
      case "viewer":
        this.permissions = {
          canViewDashboard: true,
          canViewProjects: true,
          canViewMyProjects: false,
          canManageMembers: false,
        };
        break;
    }
  }
  next();
});

module.exports = mongoose.model("OrganizationMember", organizationMemberSchema);
