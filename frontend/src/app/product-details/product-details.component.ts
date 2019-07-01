import { ProductReviewEditComponent } from '../product-review-edit/product-review-edit.component'
import { UserService } from '../Services/user.service'
import { ProductReviewService } from '../Services/product-review.service'
import { Component, Inject, OnDestroy, OnInit } from '@angular/core'
import { MAT_DIALOG_DATA, MatDialog } from '@angular/material/dialog'
import { library, dom } from '@fortawesome/fontawesome-svg-core'
import { faArrowCircleLeft, faPaperPlane, faUserEdit, faThumbsUp, faCrown } from '@fortawesome/free-solid-svg-icons'
import { FormControl, Validators } from '@angular/forms'
import { MatSnackBar } from '@angular/material/snack-bar'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { Review } from '../Models/review.model'

library.add(faPaperPlane, faArrowCircleLeft, faUserEdit, faThumbsUp, faCrown)
dom.watch()

@Component({
  selector: 'app-product-details',
  templateUrl: './product-details.component.html',
  styleUrls: ['./product-details.component.scss']
})
export class ProductDetailsComponent implements OnInit, OnDestroy {

  public author: string = 'Anonymous'
  public reviews$: any
  public userSubscription: any
  public reviewControl: FormControl = new FormControl('',[Validators.maxLength(160)])
  constructor (private dialog: MatDialog,
    @Inject(MAT_DIALOG_DATA) public data: any, private productReviewService: ProductReviewService,
    private userService: UserService, private snackBar: MatSnackBar, private snackBarHelperService: SnackBarHelperService) { }

  ngOnInit () {
    this.data = this.data.productData
    this.data.points = Math.round(this.data.price / 10)
    this.reviews$ = this.productReviewService.get(this.data.id)
    this.userSubscription = this.userService.whoAmI().subscribe((user: any) => {
      if (user && user.email) {
        this.author = user.email
      } else {
        this.author = 'Anonymous'
      }
    },(err) => console.log(err))
  }

  ngOnDestroy () {
    if (this.userSubscription) {
      this.userSubscription.unsubscribe()
    }
  }

  addReview (textPut: HTMLTextAreaElement) {

    const review = { message: textPut.value, author: this.author }

    textPut.value = ''
    this.productReviewService.create(this.data.id, review).subscribe(() => {
      this.reviews$ = this.productReviewService.get(this.data.id)
    },(err) => console.log(err))
    this.snackBarHelperService.openSnackBar('Your review has been saved', 'Ok')
  }

  editReview (review: Review) {
    this.dialog.open(ProductReviewEditComponent, {
      width: '500px',
      height: 'max-content',
      data: {
        reviewData : review
      }
    }).afterClosed().subscribe(() => this.reviews$ = this.productReviewService.get(this.data.id))
  }

  likeReview (review: Review) {
    this.productReviewService.like(review._id).subscribe(() => {
      console.log('Liked ' + review._id)
    })
    setTimeout(() => this.reviews$ = this.productReviewService.get(this.data.id), 200)
  }

  isLoggedIn () {
    return localStorage.getItem('token')
  }
}
