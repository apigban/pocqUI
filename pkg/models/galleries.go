package models

import "github.com/jinzhu/gorm"

type Gallery struct {
	gorm.Model
	UserID uint   `gorm:"not_null;index"`
	Title  string `gorm:"not_null"`
}

type GalleryService interface {
	GalleryDB
}

type GalleryDB interface {
	Create(gallery *Gallery) error
}

func NewGalleryService(db *gorm.DB) GalleryService {
	return &galleryService{
		GalleryDB: &galleryValidator{&galleryGorm{db}},
	}
}

type galleryService struct {
	GalleryDB
}

type galleryValidator struct {
	GalleryDB
}

func (gv *galleryValidator) Create(gallery *Gallery) error {
	err := runGalleryValFuncs(gallery,
		gv.titleRequired,
		gv.userIDRequired)
	if err != nil {
		return err
	}
	return gv.GalleryDB.Create(gallery)
}

func (gv *galleryValidator) userIDRequired(g *Gallery) error {
	if g.UserID <= 0 {
		return ErrUserIDRequired
	}
	return nil
}

func (gv *galleryValidator) titleRequired(g *Gallery) error {
	if g.Title == "" {
		return ErrTitleRequired
	}
	return nil
}

var _ GalleryDB = &galleryGorm{}

type galleryGorm struct {
	db *gorm.DB
}

func (gg *galleryGorm) Create(gallery *Gallery) error {
	return gg.db.Create(gallery).Error
}

type galleryValFunc func(*Gallery) error

func runGalleryValFuncs(gallery *Gallery, fns ...galleryValFunc) error {
	for _, fn := range fns {
		if err := fn(gallery); err != nil {
			return err
		}
	}
	return nil
}
