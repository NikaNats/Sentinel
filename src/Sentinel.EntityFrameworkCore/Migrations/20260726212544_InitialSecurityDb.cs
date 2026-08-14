using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.EntityFrameworkCore.Migrations
{
    /// <inheritdoc />
    public partial class InitialSecurityDb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "security_cache");

            migrationBuilder.CreateTable(
                name: "dpop_nonce_store",
                schema: "security_cache",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    nonce = table.Column<string>(type: "text", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_dpop_nonce_store", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "jti_replay_cache",
                schema: "security_cache",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_jti_replay_cache", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "session_blacklist",
                schema: "security_cache",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_session_blacklist", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_dpop_nonce_store_expires_at",
                schema: "security_cache",
                table: "dpop_nonce_store",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_jti_replay_cache_expires_at",
                schema: "security_cache",
                table: "jti_replay_cache",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_session_blacklist_expires_at",
                schema: "security_cache",
                table: "session_blacklist",
                column: "expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "dpop_nonce_store",
                schema: "security_cache");

            migrationBuilder.DropTable(
                name: "jti_replay_cache",
                schema: "security_cache");

            migrationBuilder.DropTable(
                name: "session_blacklist",
                schema: "security_cache");
        }
    }
}
