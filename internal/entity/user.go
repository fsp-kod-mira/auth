package entity

import "time"

const (
	RoleAdmin           = "admin"
	RoleRecruiter       = "recruiter"
	RoleHiringManager   = "hiring_manager"
	RoleResourceManager = "resource_manager"
)

type Role string

func (r Role) String() string {
	return string(r)
}

func (r Role) Int() int32 {
	switch r {
	case RoleAdmin:
		return 0
	case RoleRecruiter:
		return 1
	case RoleHiringManager:
		return 2
	case RoleResourceManager:
		return 3
	}
	return -1
}

type UserCredentials struct {
	Email    string `json:"email" db:"email"`
	Password string `json:"password" db:"password"`
}

type User struct {
	Id         string     `json:"id"`
	LastName   string     `json:"lastName" db:"last_name"`
	FirstName  string     `json:"firstName" db:"first_name"`
	MiddleName string     `json:"middleName" db:"middle_name"`
	Role       string     `json:"role" db:"role"`
	CreatedAt  time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt  *time.Time `json:"updatedAt" db:"updated_at"`

	UserCredentials
}

type UserClaims struct {
	Id   string `json:"id"`
	Role Role   `json:"role"`
}

type Tokens struct {
	Refresh string `json:"refresh_token"`
	Access  string `json:"access_token"`
}

func (u *User) GetClaims() *UserClaims {
	return &UserClaims{
		Id:   u.Id,
		Role: Role(u.Role),
	}
}
