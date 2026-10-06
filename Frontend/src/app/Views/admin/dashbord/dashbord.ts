import { Component, OnInit } from '@angular/core';
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
      },
      error: err => {
        this.loading=false;
        console.error(err);
      }
    });
  }
}
