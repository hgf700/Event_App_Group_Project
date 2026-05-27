import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { getCurrentUserDto } from '../../Dto/getCurrentUserDto';

@Component({
  selector: 'app-login-callback',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './login-callback.html',
  styleUrl: './login-callback.css',
})
export class LoginCallback implements OnInit {
  loading = false;
  currentUser!: getCurrentUserDto;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private userService: UserService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.generateJWTandEmail();
    this.getCurrentUser();
  }

  generateJWTandEmail(){
    const tokenFromUrl = this.route.snapshot.queryParamMap.get('jwt');
    const emailFromUrl = this.route.snapshot.queryParamMap.get('email');
    
    const tokenFromStorage = localStorage.getItem('jwt');
    const emailFromStorage = localStorage.getItem('email');

    console.log({
      tokenFromUrl,
      emailFromUrl,
      tokenFromStorage,
      emailFromStorage
    });

    // if (tokenFromUrl && emailFromUrl) {
    //   localStorage.setItem('jwt', tokenFromUrl);
    //   localStorage.setItem('email', emailFromUrl);
    // }

    if (!tokenFromUrl && !tokenFromStorage && !emailFromUrl && !emailFromStorage) {
      console.error('Brak tokena – użytkownik niezalogowany');
      return;
    }
  }

  getCurrentUser() {
    this.loading = true;
    this.userService.getCurrentUserEmail().subscribe({
      next: (data) => {
        this.currentUser = data;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się getCurrentUserEmail');
      },
    });
  }

  seedData() {
    this.router.navigate(['/seed-database']);
  }

  eventsView() {
    this.router.navigate(['/get-events']);
  }

  searchAndImportView() {
    this.router.navigate(['/search-and-import-events']);
  }

  userBoughtTickets() {
    this.router.navigate(['/user-tickets']);
  }

  editCurrentUser() {
    this.router.navigate(['/edit-user']);
  }
}
