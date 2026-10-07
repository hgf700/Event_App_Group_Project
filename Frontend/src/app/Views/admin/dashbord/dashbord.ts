import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { AdminService } from '../../../Services/AdminService';
import { getAppUsageInfoDto } from '../../../Dto/getAppUsageInfoDto';

@Component({
  selector: 'app-dashbord',
  imports: [],
  templateUrl: './dashbord.html',
  styleUrl: './dashbord.css',
})
export class Dashbord implements OnInit{
  usageInfo: getAppUsageInfoDto | null = null;
  loading = false;

  constructor(
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
        // this.cdr.detectChanges();
  ) {}

  ngOnInit(): void {
    this.loadDashboard();
  }

  loadDashboard(): void {
    this.loading = true;

    this.adminService.getAppUsageInfo().subscribe({
      next: response => {
        this.loading=false;
        this.usageInfo = response;
        this.cdr.detectChanges();
      },
      error: err => {
        this.loading=false;
        console.error(err);
      }
    });
  }
}
